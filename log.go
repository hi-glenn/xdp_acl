package main

import (
	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var zlog *zap.SugaredLogger

func InitLogger() {
	writeSyncer := getLogWriter()
	encoder := getEncoder()

	core := zapcore.NewCore(
		encoder,
		// zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), writeSyncer),
		zapcore.NewMultiWriteSyncer(writeSyncer),
		zapcore.InfoLevel,
		// zapcore.DebugLevel,
	)

	logger := zap.New(core, zap.AddCaller())

	zlog = logger.Sugar()
}

func getEncoder() zapcore.Encoder {

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	// encoderConfig.CallerKey = "linenum"
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func getLogWriter() zapcore.WriteSyncer {
	lumberJackLogger := &lumberjack.Logger{
		Filename:   "./log/acl.log",
		MaxSize:    10, // MByte
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   false,
		LocalTime:  true,
	}
	return zapcore.AddSync(lumberJackLogger)
}
