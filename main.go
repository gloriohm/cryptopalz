package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
)

func main() {
	/* challenge1()
	challenge2()
	challenge3()
	challenge4()
	challenge5()
	challenge6()
	challenge7() */
	challenge8()
}

func challenge1() {
	const input string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	const want string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	decodedHex, _ := hex.DecodeString(input)
	encodedBase := base64.StdEncoding.EncodeToString(decodedHex)

	if encodedBase == want {
		fmt.Println("success!")
	} else {
		fmt.Println("fail!")
		fmt.Println(encodedBase)
	}
}

func challenge2() {
	const input string = "1c0111001f010100061a024b53535009181c"
	const compare string = "686974207468652062756c6c277320657965"
	const want string = "746865206b696420646f6e277420706c6179"

	hex1, _ := hex.DecodeString(input)
	hex2, _ := hex.DecodeString(compare)

	result, err := xorBuf(hex1, hex2)

	if err != nil {
		fmt.Printf("failed: %s", err)
	}

	final := hex.EncodeToString(result)

	if final == want {
		fmt.Println("success!")
	} else {
		fmt.Println("fail!")
		fmt.Println(final)
	}
}

func challenge3() {
	const input string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	hex, _ := hex.DecodeString(input)
	result := singleCharXor([]byte(hex))
	fmt.Println(result)
}

func challenge4() {
	file, err := os.Open("challenge4.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	best := BestResult{}
	for scanner.Scan() {
		line := scanner.Text()
		hex, _ := hex.DecodeString(line)
		result := singleCharXor(hex)

		if result.Score > best.Score {
			best = result
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Scanner error:", err)
	}

	fmt.Println(best)
}

func challenge5() {
	const input string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	const want string = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	const key string = "ICE"

	encoded := repeatingXorEncrypter([]byte(input), []byte(key))
	encodedHex := hex.EncodeToString(encoded)

	if encodedHex == want {
		fmt.Println("success!")
	} else {
		fmt.Println("fail!")
		fmt.Println(encodedHex)
	}
}

func challenge6() {
	const test1 string = "this is a test"
	const test2 string = "wokka wokka!!!"
	const want int = 37

	hamTest, err := getHammingDistance([]byte(test1), []byte(test2))

	if err != nil {
		fmt.Println("Hamming error: ", err)
	}

	if hamTest == want {
		fmt.Println("success! hamming distance = 37")
	} else {
		fmt.Println("fail!")
		fmt.Println("hamming distance = ", hamTest)
	}

	decoded, err := readAndDecodeB64File("challenge6.txt")
	if err != nil {
		fmt.Println("Error:", err)
	}

	keysize := hammingPerKeysize(decoded)
	key := getBestCharPerPos(decoded, keysize)
	decrypted := repeatingXorEncrypter(decoded, key)
	fmt.Println(string(decrypted))
}

func challenge7() {
	key := []byte("YELLOW SUBMARINE")

	decoded, err := readAndDecodeB64File("challenge7.txt")
	if err != nil {
		fmt.Println("Error:", err)
	}

	decrypted, err := decryptECB(decoded, key)
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println(string(decrypted))
}

func challenge8() {
	file, err := os.Open("challenge4.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	blocksize := 16

	for scanner.Scan() {
		line := scanner.Text()
		hex, _ := hex.DecodeString(line)
		ecb := detectRepeatingBlock(hex, blocksize)
		if ecb {
			decypted, err := decryptECB(hex, []byte("YELLOW SUBMARINE"))
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(decypted))
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Scanner error:", err)
	}
}

func readAndDecodeB64File(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return decoded, err
	}

	return decoded, nil
}

func xorBuf(a, b []byte) ([]byte, error) {
	bufLen := len(a)
	result := make([]byte, bufLen)

	if len(a) != len(b) {
		return result, errors.New("buffers not the same length")
	}

	for i := range bufLen {
		result[i] = a[i] ^ b[i]

	}

	return result, nil
}

type BestResult struct {
	Score   float64
	Char    byte
	Decoded string
}

func singleCharXor(data []byte) BestResult {
	result := BestResult{}

	for i := range 256 {
		decoded := xorData(data, byte(i))
		score := scoreEnglishString(decoded)
		if score > result.Score {
			result.Score = score
			result.Char = byte(i)
			result.Decoded = string(decoded)
		}
	}

	return result
}

var englishFreq = map[byte]float64{
	'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51,
	'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09,
	'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
	'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23,
	'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
	'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
	'q': 0.10, 'z': 0.07, ' ': 13.00, // space is very common
}

func scoreEnglishString(data []byte) float64 {
	var score float64

	for i := range len(data) {
		char := data[i]
		if char >= 'A' && char <= 'Z' {
			char += 32 // convert to lowercase
		}

		if val, ok := englishFreq[char]; ok {
			score += val
		} else if (char < 32 || char > 126) && char != '\n' && char != '\t' {
			score -= 20.0
		} else {
			score -= 0.5
		}
	}

	return score
}

func xorData(data []byte, char byte) []byte {
	bufLen := len(data)
	result := make([]byte, bufLen)

	for i := range bufLen {
		result[i] = data[i] ^ char
	}

	return result
}

func repeatingXorEncrypter(data, key []byte) []byte {
	bufLen := len(data)
	result := make([]byte, bufLen)

	for i := range bufLen {
		result[i] = key[i%len(key)] ^ data[i]
	}

	return result
}

func getHammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("inputs not of equal length")
	}

	dist := 0
	for i := range a {
		xor := a[i] ^ b[i]
		dist += bits.OnesCount8(xor)
	}
	return dist, nil
}

func scoreKeysize(data []byte, keysize int, blocks int) float64 {
	pairs := 0
	totalDist := 0

	for i := range blocks {
		start1 := i * keysize
		start2 := (i + 1) * keysize
		if start2+keysize > len(data) {
			break
		}
		a := data[start1 : start1+keysize]
		b := data[start2 : start2+keysize]
		d, _ := getHammingDistance(a, b)
		totalDist += d
		pairs++
	}

	if pairs == 0 {
		return 999999.0
	}
	return float64(totalDist) / float64(pairs) / float64(keysize)
}

func hammingPerKeysize(data []byte) int {
	bestScore := 1e9
	var bestLen int

	for keysize := 2; keysize <= 40; keysize++ {
		score := scoreKeysize(data, keysize, 10)
		if score < bestScore {
			bestScore = score
			bestLen = keysize
		}
		fmt.Printf("Keysize %2d → score %.4f\n", keysize, score)
	}
	return bestLen
}

func getBestCharPerPos(data []byte, keysize int) []byte {
	blocks := make([][]byte, keysize)
	result := make([]byte, keysize)

	for i, b := range data {
		blockIndex := i % keysize
		blocks[blockIndex] = append(blocks[blockIndex], b)
	}

	for i, b := range blocks {
		bestChar := singleCharXor(b)
		result[i] = bestChar.Char
	}

	return result
}

func decryptECB(plaintext, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes (AES-128)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	plaintext = padder(plaintext, blockSize)
	ciphertext := make([]byte, len(plaintext))

	for bs, be := 0, blockSize; bs < len(plaintext); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(ciphertext[bs:be], plaintext[bs:be])
	}

	return ciphertext, nil
}

func padder(data []byte, blockSize int) []byte {
	remainder := len(data) % blockSize
	if remainder != 0 {
		padding := blockSize - remainder
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		return append(data, padtext...)
	} else {
		return data
	}
}

func detectRepeatingBlock(data []byte, blocksize int) bool {
	blocks := make(map[string]int)

	for i := 0; i < len(data); i += blocksize {
		if i+blocksize > len(data) {
			break
		}
		block := data[i : i+blocksize]
		blockStr := string(block)
		blocks[blockStr]++

		if blocks[blockStr] > 1 {
			return true
		}
	}

	return false
}
