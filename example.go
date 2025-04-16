package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type LunarClient struct {
	host              string
	password          string
	challengeResponse string
}

type Task struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func NewLunarClient(host, password string) *LunarClient {
	if host == "" {
		host = "http://localhost:9192"
	}
	return &LunarClient{
		host:     strings.TrimRight(host, "/"),
		password: password,
	}
}

// aes256 encrypts data using AES-256-CBC with PBKDF2
func (c *LunarClient) aes256(plaintext, password string, salt, iv []byte) (string, error) {
	key := pbkdf2.Key(
		[]byte(password),
		salt,
		10000,
		32, // 256 bits
		sha256.New,
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	bPlaintext := append([]byte(plaintext), padtext...)

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(bPlaintext))
	mode.CryptBlocks(ciphertext, bPlaintext)

	combined := append(append(salt, iv...), ciphertext...)
	return hex.EncodeToString(combined), nil
}

// Login performs the challenge-response authentication
func (c *LunarClient) Login() (bool, error) {
	req, err := http.NewRequest("GET", c.host+"/get-challenge", nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("ngrok-skip-browser-warning", "1")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to get login challenge: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to get login challenge: status %d", resp.StatusCode)
	}

	var challengeData struct {
		Challenge string `json:"challenge"`
		Salt      string `json:"salt"`
		IV        string `json:"iv"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&challengeData); err != nil {
		return false, fmt.Errorf("failed to decode challenge data: %v", err)
	}

	salt, err := hex.DecodeString(challengeData.Salt)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %v", err)
	}

	iv, err := hex.DecodeString(challengeData.IV)
	if err != nil {
		return false, fmt.Errorf("failed to decode IV: %v", err)
	}

	encrypted, err := c.aes256(challengeData.Challenge, c.password, salt, iv)
	if err != nil {
		return false, fmt.Errorf("failed to encrypt challenge: %v", err)
	}

	payload := map[string]string{"response": encrypted}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal response: %v", err)
	}

	req, err = http.NewRequest("POST", c.host+"/verify-challenge", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ngrok-skip-browser-warning", "1")

	resp, err = client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to verify challenge: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to verify challenge: status %d", resp.StatusCode)
	}

	var result struct {
		Success string `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	if result.Success == "true" {
		c.challengeResponse = encrypted
		return true, nil
	}

	return false, nil
}

// GetTasks gets list of available tasks
func (c *LunarClient) GetTasks() ([]Task, error) {
	if c.challengeResponse == "" {
		return nil, fmt.Errorf("not authenticated - call Login() first")
	}

	payload := map[string]string{"response": c.challengeResponse}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", c.host+"/get-active-tasks", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ngrok-skip-browser-warning", "1")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get tasks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get tasks: status %d", resp.StatusCode)
	}

	var tasks []Task
	if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return tasks, nil
}

// BuyToken buys a Pump.Fun, Pump.Fun AMM or Raydium AMM token
func (c *LunarClient) BuyToken(taskUUID, tokenAddress string, amount float64, poolAddress, baseVault, quoteVault string, isRaydium, isPfAmm, isPumpFun bool) error {
	if c.challengeResponse == "" {
		return fmt.Errorf("not authenticated - call Login() first")
	}

	payload := map[string]any{
		"task_uuid":          taskUUID,
		"token_address":      tokenAddress,
		"pool_address":       poolAddress, 	// pool ID (optional)
		"base_vault":         baseVault,	// base vault address (optional)
		"quote_vault":        quoteVault,	// quote vault address (optional)
		"is_raydium":         isRaydium,
		"is_pf_amm":          isPfAmm, 		
		"is_pump_fun":        isPumpFun, 
		"buy_amount":         amount, // overide the set amount in the task (optional)
		"challenge_response": c.challengeResponse,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", c.host+"/buy-token", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ngrok-skip-browser-warning", "1")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to buy token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to buy token: status %d", resp.StatusCode)
	}

	return nil
}

// SellToken sells a previously bought token
func (c *LunarClient) SellToken(taskUUID, tokenAddress string, percentage float64) error {
	if c.challengeResponse == "" {
		return fmt.Errorf("not authenticated - call Login() first")
	}

	payload := map[string]any{
		"task_uuid":          taskUUID,
		"token_address":      tokenAddress,
		"sell_percentage":    percentage,
		"challenge_response": c.challengeResponse,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", c.host+"/sell-token", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ngrok-skip-browser-warning", "1")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to sell token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to sell token: status %d", resp.StatusCode)
	}

	return nil
}