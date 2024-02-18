package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
)

func main() {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017").SetDirect(true)
	// 连接到MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)

	defer client.Disconnect(context.TODO())
	ruleDb := "rules"
	pocDb := "poc"
	responseCollection := "responseCollection"
	icoCollection := "icoCollection"
	pocCollection := "pocCollection"
	mh3File := "mh3Collection.json"
	pocFile := "pocCollection.json"
	responseCollectionFile := "responseCollection.json"
	type RuleData struct {
		Name  string `json:"name" bson:"name"`
		Value string `json:"value" bson:"value"`
		Class string `json:"class" bson:"class"`
		Type  string `json:"type" bson:"type"`
		Rule  string `json:"rule" bson:"rule"`
	}

	type Mh3Data struct {
		Name  string `json:"name" bson:"name"`
		Value string `json:"value" bson:"value"`
		Class string `json:"class" bson:"class"`
		Mmh3  string `json:"mmh3" bson:"mmh3"`
	}

	type Poc struct {
		Tag  []string `json:"tag" bson:"tag"`
		Data []byte   `json:"data" bson:"data"`
	}
	//存入指纹信息
	mh3Data, err := os.ReadFile(mh3File)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	var mh3Datas []Mh3Data
	json.Unmarshal(mh3Data, &mh3Datas)
	rdb := client.Database(ruleDb)
	mh3Col := rdb.Collection(icoCollection)
	for _, mh3 := range mh3Datas {
		mh3Col.InsertOne(context.TODO(), mh3)
	}
	respData, err := os.ReadFile(responseCollectionFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	var respDatas []RuleData
	json.Unmarshal(respData, &respDatas)
	respCol := rdb.Collection(responseCollection)
	for _, resp := range respDatas {
		respCol.InsertOne(context.TODO(), resp)
	}
	//存入poc
	var pocs []Poc
	poc, err := os.ReadFile(pocFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	pDb := client.Database(pocDb)
	pocCol := pDb.Collection(pocCollection)
	json.Unmarshal(poc, &pocs)
	for _, p := range pocs {
		pocCol.InsertOne(context.TODO(), p)
	}
}
