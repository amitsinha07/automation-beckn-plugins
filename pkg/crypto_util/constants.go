package crypto_util

const (
	IVLengthInBits             = 96
	AuthTagLengthInBits        = 128 // CANNOT BE CHANGED FOR AES-256-GCM
	KeyPairGenerationAlgorithm = "x25519"
	EncryptDecryptAlgorithm    = "aes-256-gcm"
	KeyStringFormat            = "base64"

	// Derived lengths in bytes
	AuthTagLengthInBytes = AuthTagLengthInBits / 8
	IVLengthInBytes      = IVLengthInBits / 8
)
