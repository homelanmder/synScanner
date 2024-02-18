package common

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	Client       *mongo.Client
	ResponseRule []RuleData
	IcoRule      []Mh3Data
)

func init() {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017").SetDirect(true)
	// 连接到MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return
	}
	Client = client
	ResponseRule, IcoRule = GetRules()
}

func GetRules() ([]RuleData, []Mh3Data) {
	var ruleData []RuleData
	var mh3Data []Mh3Data
	db := Client.Database(RuleDb)
	respCol := db.Collection(ResponseCollection)
	icoCol := db.Collection(IconCollection)
	filter := bson.D{
		{},
	}
	respCur, err := respCol.Find(context.TODO(), filter, &options.FindOptions{
		Projection: bson.D{{"_id", 0}},
	})
	if err != nil {
		return nil, nil
	}
	respCur.All(context.TODO(), &ruleData)

	icoCur, err := icoCol.Find(context.TODO(), filter, &options.FindOptions{
		Projection: bson.D{{"_id", 0}},
	})
	if err != nil {
		return nil, nil
	}
	icoCur.All(context.TODO(), &mh3Data)
	return ruleData, mh3Data
}

func GetPoc(tag string) (pocs []Poc) {
	filter := bson.M{"tag": bson.M{"$in": []string{tag}}}
	collection := Client.Database(PocDb).Collection(PocCollection)
	// 执行查询
	cursor, err := collection.Find(context.Background(), filter)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = cursor.All(context.TODO(), &pocs)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	return pocs
}

func SaveVulInfo(vulInfo Vul) {
	collection := Client.Database(VulDb).Collection(TaskName)
	var err error
	var count int64
	if count, err = collection.CountDocuments(context.TODO(), bson.D{{Ip, vulInfo.Ip}, {Port, vulInfo.Port}, {VulUrl, vulInfo.VulUrl}, {VulName, vulInfo.VulName}, {"weakPass.username", vulInfo.WeakPass.UserName}}); err != nil {
		if err != nil {
			return
		}
	}
	if count != 0 {
		collection.UpdateOne(context.Background(), bson.D{{Ip, vulInfo.Ip}, {Port, vulInfo.Port}, {VulName, vulInfo.VulName}, {"weakPass.username", vulInfo.WeakPass.UserName}}, bson.D{{"$set", bson.D{{"latestFindTime", vulInfo.LatestFindTime}}}})
	} else {
		if _, err = collection.InsertOne(context.Background(), vulInfo, nil); err != nil {
			fmt.Println("插入漏洞信息失败", err.Error(), vulInfo)
		}
	}

}

func SaveAsset(asset Asset) {
	collection := Client.Database(AssetDb).Collection(TaskName)
	var err error
	var count int64
	if count, err = collection.CountDocuments(context.TODO(), bson.D{{Ip, asset.Ip}, {Port, asset.Port}}); err != nil {
		return
	}
	if count != 0 {
		collection.UpdateOne(context.Background(), bson.D{{Ip, asset.Ip}, {Port, asset.Port}}, bson.D{{"$set", bson.D{{"latestFindTime", asset.LatestFindTime}}}})
	} else {
		asset.IsNew = true
		if _, err = collection.InsertOne(context.Background(), asset, nil); err != nil {
			fmt.Println("插入资产信息失败", err.Error(), asset)
		}

	}

}

func UpdateTaskInfo(taskName, key string, info interface{}) {

	collection := Client.Database(TaskDb).Collection(TaskCollection)
	filter := bson.M{"taskName": taskName}
	update := bson.M{"$set": bson.M{key: info}}
	collection.UpdateOne(context.Background(), filter, update, &options.UpdateOptions{})
}
