package iax

import (
	"encoding/binary"
)

// IAX 帧类型常量
const (
	FrameTypeDTMF     = 1
	FrameTypeVoice    = 2
	FrameTypeVideo    = 3
	FrameTypeControl  = 4
	FrameTypeNull     = 5
	FrameTypeIAXControl = 6
	FrameTypeText     = 7
	FrameTypeImage    = 8
	FrameTypeHTML     = 9
	FrameTypeComfortNoise = 10
)

// IAX 控制子类（FrameTypeIAXControl）
const (
	IAXCommandNew     = 1
	IAXCommandPing    = 2
	IAXCommandPong    = 3
	IAXCommandAck     = 4
	IAXCommandHangup  = 5
	IAXCommandReject  = 6
	IAXCommandAccept  = 7
	IAXCommandAuthReq = 8
	IAXCommandAuthRep = 9
	IAXCommandInval   = 10
	IAXCommandLagrq   = 11
	IAXCommandLagrp   = 12
	IAXCommandRegReq  = 13
	IAXCommandRegAuth = 14
	IAXCommandRegAck  = 15
	IAXCommandRegRej  = 16
	IAXCommandRel     = 17
	IAXCommandRelAck  = 18
	IAXCommandVnak    = 19
	IAXCommandDial    = 20
	IAXCommandTxreq   = 21
	IAXCommandTxacc   = 22
	IAXCommandTxrej   = 23
	IAXCommandAnsw    = 24
	IAXCommandHang    = 25
	IAXCommandToken   = 26
)

// Frame 解析后的 IAX 帧（仅头部信息）
type Frame struct {
	IsFull       bool   // 是否为完整帧
	CallNumber   uint16 // 呼叫编号
	Timestamp    uint32 // 时间戳（完整帧 32 位）
	OSeq         uint8  // 出站序号
	ISeq         uint8  // 入站序号
	FrameType    uint8  // 帧类型
	SubClass     uint8  // 子类
	Data         []byte // 剩余数据
}

// MinHeaderLen mini 帧最小长度
const MinHeaderLen = 4

// FullHeaderLen 完整帧头部长度
const FullHeaderLen = 12

// Parse 解析 IAX 帧（仅头部）
func Parse(data []byte) *Frame {
	if len(data) < MinHeaderLen {
		return nil
	}
	f := &Frame{}
	firstTwo := binary.BigEndian.Uint16(data[0:2])
	// 最高位: 0 = full frame, 1 = mini frame
	f.IsFull = (firstTwo & 0x8000) == 0
	if f.IsFull {
		if len(data) < FullHeaderLen {
			return nil
		}
		f.CallNumber = firstTwo & 0x7FFF
		f.Timestamp = binary.BigEndian.Uint32(data[2:6])
		f.OSeq = data[6]
		f.ISeq = data[7]
		f.FrameType = data[8]
		f.SubClass = data[9]
		f.Data = data[FullHeaderLen:]
	} else {
		// mini frame: [1 bit type=1][15 bits callno][16 bits ts high][8 bits subclass/ts low...]
		f.CallNumber = firstTwo & 0x7FFF
		// mini frame 的 timestamp 是 16 位
		f.Timestamp = uint32(binary.BigEndian.Uint16(data[2:4]))
		f.Data = data[MinHeaderLen:]
	}
	return f
}

// IsIAX 判断数据是否可能为 IAX 帧（简化判断）
func IsIAX(data []byte) bool {
	if len(data) < MinHeaderLen {
		return false
	}
	f := Parse(data)
	if f == nil {
		return false
	}
	if f.IsFull {
		// 完整帧的帧类型应在合法范围
		if f.FrameType > 10 {
			return false
		}
		if f.CallNumber == 0 && f.FrameType != FrameTypeIAXControl {
			return false
		}
	}
	return true
}
