package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"voxTun/internal/app/common/consts"
)

// Encode 将消息编码为字节流： [4字节长度][1字节类型][JSON载荷]
func Encode(msgType byte, payload interface{}) ([]byte, error) {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
	}
	totalLen := uint32(1 + len(body))
	buf := make([]byte, 4+1+len(body))
	binary.BigEndian.PutUint32(buf[:4], totalLen)
	buf[4] = msgType
	copy(buf[5:], body)
	return buf, nil
}

// WriteMsg 将编码后的消息写入连接
func WriteMsg(w io.Writer, msgType byte, payload interface{}) error {
	buf, err := Encode(msgType, payload)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadMsg 从连接读取一条消息，返回消息类型和 JSON 载荷
func ReadMsg(r io.Reader) (byte, []byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, nil, err
	}
	totalLen := binary.BigEndian.Uint32(lenBuf)
	if totalLen < 1 || totalLen > consts.MaxPacketSize {
		return 0, nil, fmt.Errorf("invalid message length: %d", totalLen)
	}
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return 0, nil, err
	}
	msgType := typeBuf[0]
	payloadLen := int(totalLen - 1)
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

// Decode 解析 JSON 载荷到指定结构体
func Decode(payload []byte, v interface{}) error {
	if len(payload) == 0 {
		return nil
	}
	return json.Unmarshal(payload, v)
}
