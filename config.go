package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"sync"
)

// const (
// 	opt.conf = "acl.json"
// )

func (jst *RuleArr) Load(filename string) {
	//ReadFile函数会读取文件的全部内容，并将结果以[]byte类型返回
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		zlog.Error(err.Error(), "; read config file error")
		panic(err.Error())
	}

	//读取的数据为json格式，需要进行解码
	err = json.Unmarshal(data, jst)
	if err != nil {
		zlog.Error(err.Error(), "; Unmarshal config file error")
		panic(err.Error())
	}
}

func checkFileIsExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func saveJsonFile(content string) {
	var f *os.File
	var err error

	if checkFileIsExist(opt.conf) {
		if f, err = os.OpenFile(opt.conf, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0666); err != nil {
			zlog.Info(err.Error(), "; config file is exist")
			return
		}
	} else {
		if f, err = os.Create(opt.conf); err != nil {
			zlog.Info(err.Error(), "; config file is not exist")
			return
		}
	}

	n, err := io.WriteString(f, content)
	if err != nil {
		zlog.Error(err.Error(), "; save config error")
		return
	}

	zlog.Info("save config ok; ", n, " byte")
}

func saveFile(saveFileWgPtr *sync.WaitGroup) {
	zlog.Info("🎃 saveFile goroutine start 🎃")

	for jsonFile := range bufferForJsonFile {
		zlog.Info("🎃 saveFile 🎃")

		// zlog.Info("🎃 saveFile: \n", jsonFile)

		saveJsonFile(jsonFile)
		saveFileWgPtr.Done()
	}

	zlog.Info("🎃 saveFile goroutine exit 🎃")
}
