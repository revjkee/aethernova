package groth16

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

var (
	ErrInvalidProof       = errors.New("invalid zero-knowledge proof")
	ErrInvalidInputFormat = errors.New("invalid public inputs format")
	ErrParamsNotLoaded    = errors.New("verifying key not loaded")
)

type Verifier struct {
	vk           groth16.VerifyingKey
	loadedOnce   sync.Once
	paramsLoaded bool
	paramsPath   string
	curveID      ecc.ID
	hash         [32]byte
}

// NewVerifier создаёт новый экземпляр верификатора с заданным путем к vk и кривой
func NewVerifier(paramsPath string, curve ecc.ID) *Verifier {
	return &Verifier{
		paramsPath: paramsPath,
		curveID:    curve,
	}
}

// LoadParams загружает верификационный ключ из файла
func (v *Verifier) LoadParams() error {
	var err error
	v.loadedOnce.Do(func() {
		data, readErr := ioutil.ReadFile(v.paramsPath)
		if readErr != nil {
			err = fmt.Errorf("failed to read verifying key file: %w", readErr)
			return
		}
		hash := sha256.Sum256(data)
		v.hash = hash

		switch v.curveID {
		case ecc.BN254:
			v.vk = groth16.NewVerifyingKey(ecc.BN254)
		default:
			err = fmt.Errorf("unsupported curve: %s", v.curveID.String())
			return
		}

		dec := groth16.NewDecoder(bytes.NewReader(data))
		if decodeErr := dec.Decode(&v.vk); decodeErr != nil {
			err = fmt.Errorf("failed to decode verifying key: %w", decodeErr)
			return
		}
		v.paramsLoaded = true
	})
	return err
}

// Verify проверяет zk-доказательство и возвращает true/false
func (v *Verifier) Verify(proofBytes, pubInputsJSON []byte) (bool, error) {
	if !v.paramsLoaded {
		return false, ErrParamsNotLoaded
	}

	// Декодируем доказательство
	proof := groth16.NewProof(ecc.BN254)
	if err := proof.UnmarshalBinary(proofBytes); err != nil {
		return false, fmt.Errorf("failed to unmarshal proof: %w", err)
	}

	// Парсим публичные входы
	var inputsMap map[string]interface{}
	if err := json.Unmarshal(pubInputsJSON, &inputsMap); err != nil {
		return false, fmt.Errorf("%w: %s", ErrInvalidInputFormat, err)
	}

	publicInputs := make([]interface{}, 0, len(inputsMap))
	for _, v := range inputsMap {
		publicInputs = append(publicInputs, v)
	}

	// Проверка
	err := groth16.Verify(proof, v.vk, publicInputs...)
	if err != nil {
		return false, ErrInvalidProof
	}

	return true, nil
}

// ParamsHash возвращает SHA256-хэш текущего verifying key
func (v *Verifier) ParamsHash() string {
	return base64.StdEncoding.EncodeToString(v.hash[:])
}

// Reset сбрасывает статус и позволяет заново загрузить параметры
func (v *Verifier) Reset() {
	v.loadedOnce = sync.Once{}
	v.paramsLoaded = false
	v.hash = [32]byte{}
}
