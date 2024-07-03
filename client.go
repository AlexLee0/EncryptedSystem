package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	Password      string
	PrivateKey    userlib.PKEDecKey
	SignKey       userlib.DSSignKey
	CreatedFiles  map[string]map[string]uuid.UUID
	ReceivedFiles map[string]uuid.UUID
	CreatorMap    map[string][]byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type CreatorReceivedMaps struct {
	ReceivedFiles map[string]uuid.UUID
	CreatorMap    map[string][]byte
}

type MapsHMAC struct {
	EncryptedMaps []byte
	HMAC          []byte
}

type UserHMAC struct {
	EncryptedUserStruct []byte
	HMAC                []byte
}

type File struct {
	/*
		EncryptedUUIDStart               []byte
		EncryptedUUIDEnd                 []byte
		EncryptedBlockIndex              []byte
		HMACEncryptedStartCiphertextUUID []byte
		HMACEncryptedEndCiphertextUUID   []byte
		HMACEncryptedBlockIndex          []byte*/
	UUIDStart  uuid.UUID
	UUIDEnd    uuid.UUID
	BlockIndex int
}

type FileHMAC struct {
	EncryptedFileStruct []byte
	HMAC                []byte
}

type Ciphertext struct {
	/*
		EncryptedCiphertext     []byte
		EncryptedNextUUID       []byte
		HMACEncryptedCiphertext []byte
		HMACEncryptedNextUUID   []byte*/
	Ciphertext []byte
	NextUUID   uuid.UUID
}

type CiphertextHMAC struct {
	EncryptedCiphertextStruct []byte
	HMAC                      []byte
}

type Invitation struct {
	EncryptedSourceKey        []byte
	HMACEncryptedSourceKey    []byte
	HMACEncryptedSourceKeyKey []byte
}

type InvitationHMAC struct {
	Invitation        []byte
	Signature         []byte
	HMACInvitation    []byte
	HMACInvitationKey []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var userStructAndHMAC UserHMAC
	userdata.Username = username
	userdata.Password = password

	if username == "" {
		return &userdata, errors.New("Empty username given")
	}

	// _, okPK := userlib.KeystoreGet(username + "_PK")
	// if okPK {
	// 	return &userdata, errors.New("User already exists")
	// }
	// _, okVK := userlib.KeystoreGet(username + "_VK")
	// if okVK {
	// 	return &userdata, errors.New("User already exists")
	// }

	public_key, private_key, err := userlib.PKEKeyGen()
	if err != nil {
		return &userdata, err
	}
	sign_key, verify_key, err := userlib.DSKeyGen()
	if err != nil {
		return &userdata, err
	}
	userdata.PrivateKey = private_key
	userdata.SignKey = sign_key
	userdata.CreatedFiles = make(map[string]map[string]uuid.UUID)
	userdata.ReceivedFiles = make(map[string]uuid.UUID)
	userdata.CreatorMap = make(map[string][]byte)
	creatorMap := userdata.CreatorMap
	receviedMap := userdata.ReceivedFiles

	err = userlib.KeystoreSet(username+"_PK", public_key)
	if err != nil {
		return &userdata, err
	}
	err = userlib.KeystoreSet(username+"_VK", verify_key)
	if err != nil {
		return &userdata, err
	}

	bytesUserStruct, err := json.Marshal(userdata)
	if err != nil {
		return &userdata, err
	}

	sourceKey := userlib.Argon2Key([]byte(username), []byte(password), 16)
	symKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return
	}
	symKey = symKey[0:16]
	encryptedUserStruct := userlib.SymEnc(symKey, userlib.RandomBytes(16), bytesUserStruct)
	userStructAndHMAC.EncryptedUserStruct = encryptedUserStruct

	macKey, err := userlib.HashKDF(sourceKey, []byte("HMAC"))
	if err != nil {
		return &userdata, err
	}
	macKey = macKey[0:16]

	hmacOfEncryptedUserStruct, err := userlib.HMACEval(macKey, encryptedUserStruct)
	if err != nil {
		return &userdata, err
	}

	userStructAndHMAC.HMAC = hmacOfEncryptedUserStruct

	bytesUserHMAC, err := json.Marshal(userStructAndHMAC)
	if err != nil {
		return &userdata, err
	}

	sourceKeyUUID, err := uuid.FromBytes(sourceKey)
	if err != nil {
		return &userdata, err
	}
	userlib.DatastoreSet(sourceKeyUUID, bytesUserHMAC)

	userdata.UpdateMaps(creatorMap, receviedMap)
	return &userdata, nil
}

// Helper method for updating Datastore with updated User
func UpdateUser(userdata *User) error {
	bytesUserStruct, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	username := userdata.Username
	password := userdata.Password
	var userStructAndHMAC UserHMAC

	sourceKey := userlib.Argon2Key([]byte(username), []byte(password), 16)
	symKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return err
	}
	symKey = symKey[0:16]
	encryptedUserStruct := userlib.SymEnc(symKey, userlib.RandomBytes(16), bytesUserStruct)
	userStructAndHMAC.EncryptedUserStruct = encryptedUserStruct

	macKey, err := userlib.HashKDF(sourceKey, []byte("HMAC"))
	if err != nil {
		return err
	}
	macKey = macKey[0:16]

	hmacOfEncryptedUserStruct, err := userlib.HMACEval(macKey, encryptedUserStruct)
	if err != nil {
		return err
	}

	userStructAndHMAC.HMAC = hmacOfEncryptedUserStruct

	bytesUserHMAC, err := json.Marshal(userStructAndHMAC)
	if err != nil {
		return err
	}

	sourceKeyUUID, err := uuid.FromBytes(sourceKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(sourceKeyUUID, bytesUserHMAC)

	return nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var userStructAndHMAC UserHMAC

	if username == "" {
		return &userdata, errors.New("Empty username given")
	}

	// _, okPK := userlib.KeystoreGet(username + "_PK")
	// if !okPK {
	// 	return &userdata, errors.New("User does not exist")
	// }
	// _, okVK := userlib.KeystoreGet(username + "_VK")
	// if !okVK {
	// 	return &userdata, errors.New("User does not exist")
	// }

	sourceKey := userlib.Argon2Key([]byte(username), []byte(password), 16)
	sourceKeyUUID, err := uuid.FromBytes(sourceKey)
	if err != nil {
		return &userdata, err
	}
	bytesUserHMAC, ok := userlib.DatastoreGet(sourceKeyUUID)
	if !ok {
		return &userdata, errors.New("User does not exist")
	}

	err = json.Unmarshal(bytesUserHMAC, &userStructAndHMAC)
	if err != nil {
		return &userdata, err
	}

	// Check HMAC of User struct
	macKey, err := userlib.HashKDF(sourceKey, []byte("HMAC"))
	if err != nil {
		return &userdata, err
	}

	macKey = macKey[0:16]
	hmacOfEncryptedUserStruct, err := userlib.HMACEval(macKey, userStructAndHMAC.EncryptedUserStruct)
	if err != nil {
		return &userdata, err
	}
	sameHMAC := userlib.HMACEqual(hmacOfEncryptedUserStruct, userStructAndHMAC.HMAC)
	if !sameHMAC {
		return &userdata, errors.New("User Struct may be tampered")
	}

	symKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return &userdata, err
	}
	symKey = symKey[0:16]
	bytesUserStruct := userlib.SymDec(symKey, userStructAndHMAC.EncryptedUserStruct)
	err = json.Unmarshal(bytesUserStruct, &userdata)
	if err != nil {
		return &userdata, err
	}

	userdataptr = &userdata

	userlib.DatastoreSet(sourceKeyUUID, bytesUserHMAC)

	return userdataptr, nil
}

func (userdata *User) UpdateMaps(creatorMap map[string][]byte, receivedMap map[string]uuid.UUID) error {
	var maps MapsHMAC
	mapKey := userlib.Argon2Key([]byte(userdata.Username+"Maps"), []byte(userdata.Password), 16)
	mapSymKey, err := userlib.HashKDF(mapKey, []byte("encryption"))
	if err != nil {
		return err
	}
	mapSymKey = mapSymKey[:16]

	var cr CreatorReceivedMaps
	cr.CreatorMap = creatorMap
	cr.ReceivedFiles = receivedMap
	crByte, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	encryptedMaps := userlib.SymEnc(mapSymKey, userlib.RandomBytes(16), crByte)
	maps.EncryptedMaps = encryptedMaps

	mapsMacKey, err := userlib.HashKDF(mapKey, []byte("HMAC"))
	if err != nil {
		return err
	}
	mapsMacKey = mapsMacKey[0:16]
	hmacOfMaps, err := userlib.HMACEval(mapsMacKey, encryptedMaps)
	if err != nil {
		return err
	}
	maps.HMAC = hmacOfMaps

	mapsByte, err := json.Marshal(maps)
	if err != nil {
		return err
	}

	mapsStorageKey, err := uuid.FromBytes(mapKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(mapsStorageKey, mapsByte)

	return nil
}

func (userdata *User) GetMaps() (result *CreatorReceivedMaps, err error) {
	var maps MapsHMAC
	mapKey := userlib.Argon2Key([]byte(userdata.Username+"Maps"), []byte(userdata.Password), 16)
	mapStorageKey, err := uuid.FromBytes(mapKey)
	if err != nil {
		return nil, err
	}

	// Get raw mapHMAC
	byteMapHMAC, ok := userlib.DatastoreGet(mapStorageKey)
	if !ok {
		return nil, errors.New("No Maps")
	}
	err = json.Unmarshal(byteMapHMAC, &maps)
	if err != nil {
		return nil, err
	}

	// Check HMAC
	mapMacKey, err := userlib.HashKDF(mapKey, []byte("HMAC"))
	if err != nil {
		return nil, err
	}
	mapMacKey = mapMacKey[0:16]
	hmacOfMaps, err := userlib.HMACEval(mapMacKey, maps.EncryptedMaps)
	if err != nil {
		return nil, err
	}
	sameHMAC := userlib.HMACEqual(hmacOfMaps, maps.HMAC)
	if !sameHMAC {
		return nil, errors.New("Creator Map or Received Files tampered")
	}

	// Decrypt
	mapSymKey, err := userlib.HashKDF(mapKey, []byte("encryption"))
	if err != nil {
		return nil, err
	}
	mapSymKey = mapSymKey[:16]
	byteMaps := userlib.SymDec(mapSymKey, maps.EncryptedMaps)
	var res CreatorReceivedMaps
	json.Unmarshal(byteMaps, &res)

	return &res, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userdata = GetUpatedUser(userdata)

	var sourceKey []byte
	//maps, err := userdata.GetMaps()
	//if err != nil {
	//	return err
	//}
	sourceKey, ok := userdata.CreatorMap[filename]
	if !ok {
		// For owner
		_, ok := userdata.ReceivedFiles[filename]
		if !ok {
			sourceKey = userlib.RandomBytes(16)
			// Updating User's owned files
			userdata.CreatedFiles[filename] = make(map[string]uuid.UUID)
			userdata.CreatorMap[filename] = sourceKey
			//maps.CreatorMap[filename] = sourceKey
			userdata.UpdateMaps(userdata.CreatorMap, userdata.ReceivedFiles)
		} else {
			invitationHMACUUID, ok := userdata.ReceivedFiles[filename]
			// For receivers
			invitationHMACBytes, ok := userlib.DatastoreGet(invitationHMACUUID)
			if !ok {
				return errors.New("User Did Not Receive/Accept Invitation")
			}
			var invitationHMAC InvitationHMAC
			var invitation Invitation
			err := json.Unmarshal(invitationHMACBytes, &invitationHMAC)
			if err != nil {
				return err
			}

			//HMAC Check for InvitationHMAC
			HMACForInvitationHMAC, err := userlib.HMACEval(invitationHMAC.HMACInvitationKey, invitationHMAC.Invitation)
			if err != nil {
				return err
			}
			sameHMAC := userlib.HMACEqual(HMACForInvitationHMAC, invitationHMAC.HMACInvitation)
			if !sameHMAC {
				return errors.New("Invitation HMAC may be tampered")
			}

			//Retrieve Invitation Struct
			err = json.Unmarshal(invitationHMAC.Invitation, &invitation)
			if err != nil {
				return err
			}

			//HMAC Check for Invitation
			HMACForEncryptedSourceKey, err := userlib.HMACEval(invitation.HMACEncryptedSourceKeyKey, invitation.EncryptedSourceKey)
			if err != nil {
				return err
			}
			sameHMACforInvitation := userlib.HMACEqual(HMACForEncryptedSourceKey, invitation.HMACEncryptedSourceKey)
			if !sameHMACforInvitation {
				return errors.New("Invitation may be tampered")
			}

			//Retrieve Source Key
			sourceKey, err = userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedSourceKey)
			if err != nil {
				return err
			}
		}
	}

	storageKey, err := uuid.FromBytes(sourceKey)
	if err != nil {
		return err
	}

	var file File

	// Encrypts startUUID
	startUUID := uuid.New()
	file.UUIDStart = startUUID
	currentUUID := startUUID

	// Divides the ciphertext into 4 byte blocks
	blockIndex := 0
	blockSize := 4

	for blockIndex < len(content)/blockSize {
		var intermediateCiphertext Ciphertext
		//----------------------------TRYING NEW METHOD-------------------------------------------
		intermediateCiphertext.Ciphertext = content[blockIndex*blockSize : (blockIndex+1)*blockSize]
		nextUUID := uuid.New()
		intermediateCiphertext.NextUUID = nextUUID

		// Encrypting entire ciphertext struct
		symKey, err := userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", blockIndex)))
		symKey = symKey[:16]
		bytesIntermediate, err := json.Marshal(intermediateCiphertext)
		if err != nil {
			return err
		}
		var interCipherHMAC CiphertextHMAC
		encryptedCiphertext := userlib.SymEnc(symKey, userlib.RandomBytes(16), bytesIntermediate)
		interCipherHMAC.EncryptedCiphertextStruct = encryptedCiphertext

		// HMAC entire ciphertext struct
		macKey, err := userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", blockIndex)))
		if err != nil {
			return err
		}
		macKey = macKey[0:16]
		HMACofEncryptedCiphertext, err := userlib.HMACEval(macKey, encryptedCiphertext)
		if err != nil {
			return err
		}
		interCipherHMAC.HMAC = HMACofEncryptedCiphertext

		// Storing interCipherHMAC
		bytesInterHMAC, err := json.Marshal(interCipherHMAC)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(currentUUID, bytesInterHMAC)

		// Gets ready for next iteration
		currentUUID = nextUUID
		blockIndex++
	}

	// Ciphertext struct for the remaining < blockSize bytes
	var finalCiphertext Ciphertext
	finalCiphertext.Ciphertext = content[blockIndex*blockSize:]
	finalCiphertext.NextUUID = uuid.Nil

	// Encrypt the ciphertext struct
	ciphertextEncryptionKey, err := userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", blockIndex)))
	if err != nil {
		return err
	}
	ciphertextEncryptionKey = ciphertextEncryptionKey[0:16]
	byteFinalCipher, err := json.Marshal(finalCiphertext)
	if err != nil {
		return err
	}
	ciphertextEncrypted := userlib.SymEnc(ciphertextEncryptionKey, userlib.RandomBytes(16), byteFinalCipher)
	var HMACFinalCipher CiphertextHMAC
	HMACFinalCipher.EncryptedCiphertextStruct = ciphertextEncrypted

	// HMAC the final cipher
	macKey, err := userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", blockIndex)))
	if err != nil {
		return err
	}
	macKey = macKey[0:16]
	HMACofEncryptedCiphertext, err := userlib.HMACEval(macKey, ciphertextEncrypted)
	if err != nil {
		return err
	}
	HMACFinalCipher.HMAC = HMACofEncryptedCiphertext

	// Storing HMACFinalCipher
	bytesFinalHMAC, err := json.Marshal(HMACFinalCipher)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(currentUUID, bytesFinalHMAC)

	file.BlockIndex = blockIndex
	file.UUIDEnd = currentUUID

	// Encrypt File
	fileEncryptionKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return err
	}
	fileEncryptionKey = fileEncryptionKey[0:16]
	byteFile, err := json.Marshal(file)
	if err != nil {
		return err
	}
	fileEncrypted := userlib.SymEnc(fileEncryptionKey, userlib.RandomBytes(16), byteFile)
	var HMACFile FileHMAC
	HMACFile.EncryptedFileStruct = fileEncrypted

	// HMAC File
	macKey, err = userlib.HashKDF(sourceKey, []byte("HMAC"))
	if err != nil {
		return err
	}
	macKey = macKey[0:16]
	HMACofEncryptedFile, err := userlib.HMACEval(macKey, fileEncrypted)
	if err != nil {
		return err
	}
	HMACFile.HMAC = HMACofEncryptedFile

	// Storing HMACFinalCipher
	bytesFileHMAC, err := json.Marshal(HMACFile)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, bytesFileHMAC)

	UpdateUser(userdata)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	// Get Updated CreatorMap
	/*sourceKey for owner vs children*/
	var sourceKey []byte
	maps, err := userdata.GetMaps()
	if err != nil {
		return err
	}

	sourceKey, ok := maps.CreatorMap[filename]
	if !ok {
		// For receivers
		invitationHMACUUID := maps.ReceivedFiles[filename]
		invitationHMACBytes, ok := userlib.DatastoreGet(invitationHMACUUID)
		if !ok {
			return errors.New("User Did Not Receive/Accept Invitation")
		}
		var invitationHMAC InvitationHMAC
		var invitation Invitation
		err := json.Unmarshal(invitationHMACBytes, &invitationHMAC)
		if err != nil {
			return err
		}

		//HMAC Check for InvitationHMAC
		HMACForInvitationHMAC, err := userlib.HMACEval(invitationHMAC.HMACInvitationKey, invitationHMAC.Invitation)
		if err != nil {
			return err
		}
		sameHMAC := userlib.HMACEqual(HMACForInvitationHMAC, invitationHMAC.HMACInvitation)
		if !sameHMAC {
			return errors.New("Invitation HMAC may be tampered")
		}

		//Retrieve Invitation Struct
		err = json.Unmarshal(invitationHMAC.Invitation, &invitation)
		if err != nil {
			return err
		}

		//HMAC Check for Invitation
		HMACForEncryptedSourceKey, err := userlib.HMACEval(invitation.HMACEncryptedSourceKeyKey, invitation.EncryptedSourceKey)
		if err != nil {
			return err
		}
		sameHMACforInvitation := userlib.HMACEqual(HMACForEncryptedSourceKey, invitation.HMACEncryptedSourceKey)
		if !sameHMACforInvitation {
			return errors.New("Invitation may be tampered")
		}

		//Retrieve Source Key
		sourceKey, err = userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedSourceKey)
		if err != nil {
			return err
		}
	}

	storageKey, err := uuid.FromBytes(sourceKey)
	if err != nil {
		return err
	}

	var fileHMAC FileHMAC
	// Get raw encrypted fileHMAC
	fileHMACByte, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New("File does not exist")
	}
	err = json.Unmarshal(fileHMACByte, &fileHMAC)
	if err != nil {
		return err
	}
	/*
		// Check HMAC of file
		fileHMACKey, err := userlib.HashKDF(sourceKey, []byte("HMAC"))
		fileHMACKey = fileHMACKey[0:16]
		if err != nil {
			return err
		}
		HMACFile, err := userlib.HMACEval(fileHMACKey, fileHMAC.EncryptedFileStruct)
		if err != nil {
			return err
		}
		sameFileHMAC := userlib.HMACEqual(HMACFile, fileHMAC.HMAC)
		if !sameFileHMAC {
			return errors.New("File Struct may be tampered")
		}
	*/
	// Decrypt File
	fileSymKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return err
	}
	fileSymKey = fileSymKey[0:16]
	fileByte := userlib.SymDec(fileSymKey, fileHMAC.EncryptedFileStruct)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return err
	}
	blockIndex := file.BlockIndex
	currentUUID := file.UUIDEnd

	// Get raw endCiphertextHMAC
	endCiphertextHMACByte, ok := userlib.DatastoreGet(currentUUID)
	if !ok {
		return errors.New("Ciphertext does not exist")
	}
	var endCiphertextHMAC CiphertextHMAC
	err = json.Unmarshal(endCiphertextHMACByte, &endCiphertextHMAC)
	if err != nil {
		return err
	}
	/*
		// Check HMAC of Ciphertext
		macKey, err := userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", blockIndex)))
		if err != nil {
			return err
		}
		macKey = macKey[0:16]
		HMACofEncryptedCiphertext, err := userlib.HMACEval(macKey, endCiphertextHMAC.EncryptedCiphertextStruct)
		if err != nil {
			return err
		}
		sameEndCipherHMAC := userlib.HMACEqual(HMACofEncryptedCiphertext, endCiphertextHMAC.HMAC)
		if !sameEndCipherHMAC {
			return errors.New("Ciphertext Struct may be tampered")
		}*/

	// Decrypt Ciphertext
	cipherSymKey, err := userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", blockIndex)))
	if err != nil {
		return err
	}
	cipherSymKey = cipherSymKey[0:16]
	endCipherByte := userlib.SymDec(cipherSymKey, endCiphertextHMAC.EncryptedCiphertextStruct)
	var endCipher Ciphertext
	err = json.Unmarshal(endCipherByte, &endCipher)
	if err != nil {
		return err
	}

	// Generate and update ciphertext
	nextUUID := uuid.New()
	endCipher.NextUUID = nextUUID

	// Encrypt end ciphertext
	ciphertextEncryptionKey, err := userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", blockIndex)))
	if err != nil {
		return err
	}
	ciphertextEncryptionKey = ciphertextEncryptionKey[0:16]
	byteEndCipher, err := json.Marshal(endCipher)
	if err != nil {
		return err
	}
	ciphertextEncrypted := userlib.SymEnc(ciphertextEncryptionKey, userlib.RandomBytes(16), byteEndCipher)
	endCiphertextHMAC.EncryptedCiphertextStruct = ciphertextEncrypted

	// HMAC the end cipher
	macKey, err := userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", blockIndex)))
	if err != nil {
		return err
	}
	macKey = macKey[0:16]
	HMACofEndCiphertext, err := userlib.HMACEval(macKey, ciphertextEncrypted)
	if err != nil {
		return err
	}
	endCiphertextHMAC.HMAC = HMACofEndCiphertext
	bytesEndHMAC, err := json.Marshal(endCiphertextHMAC)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(currentUUID, bytesEndHMAC)

	// Update currentUUID to nextUUID
	currentUUID = nextUUID
	blockIndex++
	// Divides the ciphertext into blockSize * byte blocks
	appendBlockIndex := 0
	blockSize := 100000
	for appendBlockIndex < len(content)/blockSize {
		var intermediateCiphertext Ciphertext
		intermediateCiphertext.Ciphertext = content[appendBlockIndex*blockSize : (appendBlockIndex+1)*blockSize]
		nextUUID := uuid.New()
		intermediateCiphertext.NextUUID = nextUUID

		// Encrypting entire ciphertext struct
		symKey, err := userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", blockIndex+appendBlockIndex)))
		symKey = symKey[:16]
		bytesIntermediate, err := json.Marshal(intermediateCiphertext)
		if err != nil {
			return err
		}
		var interCipherHMAC CiphertextHMAC
		encryptedCiphertext := userlib.SymEnc(symKey, userlib.RandomBytes(16), bytesIntermediate)
		interCipherHMAC.EncryptedCiphertextStruct = encryptedCiphertext

		// HMAC entire ciphertext struct
		macKey, err := userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", blockIndex+appendBlockIndex)))
		if err != nil {
			return err
		}
		macKey = macKey[0:16]
		HMACofEncryptedCiphertext, err := userlib.HMACEval(macKey, encryptedCiphertext)
		if err != nil {
			return err
		}
		interCipherHMAC.HMAC = HMACofEncryptedCiphertext

		// Storing interCipherHMAC
		bytesInterHMAC, err := json.Marshal(interCipherHMAC)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(currentUUID, bytesInterHMAC)

		// Gets ready for next iteration
		currentUUID = nextUUID
		appendBlockIndex++
	}

	// Ciphertext struct for the remaining < blockSize bytes
	var finalCiphertext Ciphertext
	finalCiphertext.Ciphertext = content[appendBlockIndex*blockSize:]
	finalCiphertext.NextUUID = uuid.Nil

	// Encrypt the ciphertext struct
	ciphertextEncryptionKey, err = userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", appendBlockIndex+blockIndex)))
	if err != nil {
		return err
	}
	ciphertextEncryptionKey = ciphertextEncryptionKey[0:16]
	byteFinalCipher, err := json.Marshal(finalCiphertext)
	if err != nil {
		return err
	}
	ciphertextEncrypted = userlib.SymEnc(ciphertextEncryptionKey, userlib.RandomBytes(16), byteFinalCipher)
	var HMACFinalCipher CiphertextHMAC
	HMACFinalCipher.EncryptedCiphertextStruct = ciphertextEncrypted

	// HMAC the final cipher
	macKey, err = userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", appendBlockIndex+blockIndex)))
	if err != nil {
		return err
	}
	macKey = macKey[0:16]
	HMACofEncryptedCiphertext, err := userlib.HMACEval(macKey, ciphertextEncrypted)
	if err != nil {
		return err
	}
	HMACFinalCipher.HMAC = HMACofEncryptedCiphertext

	// Storing HMACFinalCipher
	bytesFinalHMAC, err := json.Marshal(HMACFinalCipher)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(currentUUID, bytesFinalHMAC)

	// Store updated blockIndex and endUUID
	file.BlockIndex = blockIndex + appendBlockIndex
	file.UUIDEnd = currentUUID

	// Encrypt File
	fileEncryptionKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return err
	}
	fileEncryptionKey = fileEncryptionKey[0:16]
	byteFile, err := json.Marshal(file)
	if err != nil {
		return err
	}
	fileEncrypted := userlib.SymEnc(fileEncryptionKey, userlib.RandomBytes(16), byteFile)
	var HMACUpdatedFile FileHMAC
	HMACUpdatedFile.EncryptedFileStruct = fileEncrypted

	// HMAC File
	macKey, err = userlib.HashKDF(sourceKey, []byte("HMAC"))
	if err != nil {
		return err
	}
	macKey = macKey[0:16]
	HMACofEncryptedFile, err := userlib.HMACEval(macKey, fileEncrypted)
	if err != nil {
		return err
	}
	HMACUpdatedFile.HMAC = HMACofEncryptedFile

	// Storing HMACFinalCipher
	bytesFileHMAC, err := json.Marshal(HMACUpdatedFile)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, bytesFileHMAC)
	//UpdateUser(userdata)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userdata = GetUpatedUser(userdata)
	var file File
	var result []byte
	var sourceKey []byte
	if err != nil {
		return nil, err
	}
	sourceKey, ok := userdata.CreatorMap[filename]
	if !ok {
		invitationHMACUUID := userdata.ReceivedFiles[filename]
		invitationHMACBytes, ok := userlib.DatastoreGet(invitationHMACUUID)
		if !ok {
			return nil, errors.New("User Did Not Receive/Accept Invitation")
		}
		var invitationHMAC InvitationHMAC
		var invitation Invitation

		err := json.Unmarshal(invitationHMACBytes, &invitationHMAC)
		if err != nil {
			return nil, err
		}

		//HMAC Check for InvitationHMAC
		HMACForInvitationHMAC, err := userlib.HMACEval(invitationHMAC.HMACInvitationKey, invitationHMAC.Invitation)
		if err != nil {
			return nil, err
		}
		sameHMAC := userlib.HMACEqual(HMACForInvitationHMAC, invitationHMAC.HMACInvitation)
		if !sameHMAC {
			return nil, errors.New("Invitation HMAC may be tampered")
		}

		//Retrieve Invitation Struct
		err = json.Unmarshal(invitationHMAC.Invitation, &invitation)
		if err != nil {
			return nil, err
		}

		//HMAC Check for Invitation
		HMACForEncryptedSourceKey, err := userlib.HMACEval(invitation.HMACEncryptedSourceKeyKey, invitation.EncryptedSourceKey)
		if err != nil {
			return nil, err
		}
		sameHMACforInvitation := userlib.HMACEqual(HMACForEncryptedSourceKey, invitation.HMACEncryptedSourceKey)
		if !sameHMACforInvitation {
			return nil, errors.New("Invitation may be tampered")
		}

		//Retrieve Source Key
		sourceKey, err = userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedSourceKey)
		if err != nil {
			return nil, err
		}
	}

	storageKey, err := uuid.FromBytes(sourceKey)
	if err != nil {
		return nil, err
	}

	var fileHMAC FileHMAC
	// Get raw encrypted fileHMAC
	fileHMACByte, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New("File does not exist")
	}
	err = json.Unmarshal(fileHMACByte, &fileHMAC)
	if err != nil {
		return nil, err
	}

	// Check HMAC of file
	fileHMACKey, err := userlib.HashKDF(sourceKey, []byte("HMAC"))
	fileHMACKey = fileHMACKey[0:16]
	if err != nil {
		return nil, err
	}
	HMACFile, err := userlib.HMACEval(fileHMACKey, fileHMAC.EncryptedFileStruct)
	if err != nil {
		return nil, err
	}
	sameFileHMAC := userlib.HMACEqual(HMACFile, fileHMAC.HMAC)
	if !sameFileHMAC {
		return nil, errors.New("File Struct may be tampered")
	}

	// Decrypt File
	fileSymKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return nil, err
	}
	fileSymKey = fileSymKey[0:16]
	fileByte := userlib.SymDec(fileSymKey, fileHMAC.EncryptedFileStruct)
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return nil, err
	}

	// Get raw first CiphertextHMAC
	startCiphertextHMACByte, ok := userlib.DatastoreGet(file.UUIDStart)
	if !ok {
		return nil, errors.New("Ciphertext does not exist")
	}
	var startCiphertextHMAC CiphertextHMAC
	err = json.Unmarshal(startCiphertextHMACByte, &startCiphertextHMAC)
	if err != nil {
		return nil, err
	}

	// Check HMAC of Ciphertext
	macKey, err := userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", 0)))
	if err != nil {
		return nil, err
	}
	macKey = macKey[0:16]
	HMACofEncryptedCiphertext, err := userlib.HMACEval(macKey, startCiphertextHMAC.EncryptedCiphertextStruct)
	if err != nil {
		return nil, err
	}
	sameStartCipherHMAC := userlib.HMACEqual(HMACofEncryptedCiphertext, startCiphertextHMAC.HMAC)
	if !sameStartCipherHMAC {
		return nil, errors.New("Ciphertext Struct may be tampered")
	}

	// Decrypt Ciphertext
	cipherSymKey, err := userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", 0)))
	if err != nil {
		return nil, err
	}
	cipherSymKey = cipherSymKey[0:16]
	startCipherByte := userlib.SymDec(cipherSymKey, startCiphertextHMAC.EncryptedCiphertextStruct)
	var startCipher Ciphertext
	err = json.Unmarshal(startCipherByte, &startCipher)
	if err != nil {
		return nil, err
	}

	blockIndex := 0
	nextUUID := startCipher.NextUUID
	currentCiphertext := startCipher

	// Iterator through all ciphertext blocks
	for nextUUID != uuid.Nil {
		currentResult := currentCiphertext.Ciphertext
		result = append(result, currentResult...)

		// PREP FOR NEXT ITERATION
		blockIndex++

		// Get next block
		nextCiphertextHMACByte, ok := userlib.DatastoreGet(currentCiphertext.NextUUID)
		if !ok {
			return nil, errors.New("Ciphertext does not exist")
		}
		var nextCiphertextHMAC CiphertextHMAC
		err = json.Unmarshal(nextCiphertextHMACByte, &nextCiphertextHMAC)
		if err != nil {
			return nil, err
		}

		// Check HMAC of Ciphertext
		macKey, err := userlib.HashKDF(sourceKey, []byte("HMACBlock"+fmt.Sprintf("%d", blockIndex)))
		if err != nil {
			return nil, err
		}
		macKey = macKey[0:16]
		HMACofEncryptedCiphertext, err := userlib.HMACEval(macKey, nextCiphertextHMAC.EncryptedCiphertextStruct)
		if err != nil {
			return nil, err
		}
		sameCipherHMAC := userlib.HMACEqual(HMACofEncryptedCiphertext, nextCiphertextHMAC.HMAC)
		if !sameCipherHMAC {
			return nil, errors.New("Ciphertext Struct may be tampered")
		}

		// Decrypt Ciphertext
		cipherSymKey, err := userlib.HashKDF(sourceKey, []byte("encryptionBlock"+fmt.Sprintf("%d", blockIndex)))
		if err != nil {
			return nil, err
		}
		cipherSymKey = cipherSymKey[0:16]
		nextCipherByte := userlib.SymDec(cipherSymKey, nextCiphertextHMAC.EncryptedCiphertextStruct)

		err = json.Unmarshal(nextCipherByte, &currentCiphertext)
		if err != nil {
			return nil, err
		}
		nextUUID = currentCiphertext.NextUUID
	}

	currentResult := currentCiphertext.Ciphertext
	result = append(result, currentResult...)

	return result, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	userdata = GetUpatedUser(userdata)
	//owner perspective

	var invitation Invitation

	//Retrieve Source Key and Ecrypt with Recipient Public Key

	var sourceKey []byte
	if err != nil {
		return uuid.Nil, err
	}
	sourceKey, ok := userdata.CreatorMap[filename]
	if !ok {
		invitationHMACUUID := userdata.ReceivedFiles[filename]
		invitationHMACBytes, ok := userlib.DatastoreGet(invitationHMACUUID)
		if !ok {
			return uuid.Nil, errors.New("User Did Not Receive/Accept Invitation")
		}
		var invitationHMAC InvitationHMAC
		var invitation Invitation

		err := json.Unmarshal(invitationHMACBytes, &invitationHMAC)
		if err != nil {
			return uuid.Nil, err
		}

		//HMAC Check for InvitationHMAC
		HMACForInvitationHMAC, err := userlib.HMACEval(invitationHMAC.HMACInvitationKey, invitationHMAC.Invitation)
		if err != nil {
			return uuid.Nil, err
		}
		sameHMAC := userlib.HMACEqual(HMACForInvitationHMAC, invitationHMAC.HMACInvitation)
		if !sameHMAC {
			return uuid.Nil, errors.New("Invitation HMAC may be tampered")
		}

		//Retrieve Invitation Struct
		err = json.Unmarshal(invitationHMAC.Invitation, &invitation)
		if err != nil {
			return uuid.Nil, err
		}

		//HMAC Check for Invitation
		HMACForEncryptedSourceKey, err := userlib.HMACEval(invitation.HMACEncryptedSourceKeyKey, invitation.EncryptedSourceKey)
		if err != nil {
			return uuid.Nil, err
		}
		sameHMACforInvitation := userlib.HMACEqual(HMACForEncryptedSourceKey, invitation.HMACEncryptedSourceKey)
		if !sameHMACforInvitation {
			return uuid.Nil, errors.New("Invitation may be tampered")
		}

		//Retrieve Source Key
		sourceKey, err = userlib.PKEDec(userdata.PrivateKey, invitation.EncryptedSourceKey)
		if err != nil {
			return uuid.Nil, err
		}
	}

	recipientPK, ok := userlib.KeystoreGet(recipientUsername + "_PK")
	if !ok {
		return uuid.Nil, errors.New("Recipient Does Not Exist")
	}
	encryptedSourceKey, err := userlib.PKEEnc(recipientPK, sourceKey)
	if err != nil {
		return uuid.Nil, err
	}
	invitation.EncryptedSourceKey = encryptedSourceKey

	//HMAC Encrypted Source Key
	soureKeyHMACKey := userlib.RandomBytes(16)
	sourceKeyHMAC, err := userlib.HMACEval(soureKeyHMACKey, encryptedSourceKey)
	if err != nil {
		return uuid.Nil, err
	}
	invitation.HMACEncryptedSourceKeyKey = soureKeyHMACKey
	invitation.HMACEncryptedSourceKey = sourceKeyHMAC

	//Encrypt Entire Invitation Struct
	var invitationHMAC InvitationHMAC

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}

	signature, err := userlib.DSSign(userdata.SignKey, invitationBytes)
	if err != nil {
		return uuid.Nil, err
	}
	invitationHMAC.Invitation = invitationBytes
	invitationHMAC.Signature = signature

	//HMAC Invitation
	invitationHMACKey := userlib.RandomBytes(16)
	invitationStructHMAC, err := userlib.HMACEval(invitationHMACKey, invitationHMAC.Invitation)
	if err != nil {
		return uuid.Nil, err
	}
	invitationHMAC.HMACInvitation = invitationStructHMAC
	invitationHMAC.HMACInvitationKey = invitationHMACKey

	//Store InvitationHMAC Struct into DataStore
	uuidInvitationHMAC := uuid.New()
	invitationHMACBytes, err := json.Marshal(invitationHMAC)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(uuidInvitationHMAC, invitationHMACBytes)

	//update user owner tree
	if userdata.CreatedFiles[filename] == nil {
		userdata.CreatedFiles[filename] = make(map[string]uuid.UUID)
	}
	userdata.CreatedFiles[filename][recipientUsername] = uuidInvitationHMAC
	UpdateUser(userdata)
	return uuidInvitationHMAC, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	userdata = GetUpatedUser(userdata)
	_, ok := userdata.CreatorMap[filename]
	if ok {
		return errors.New("File with Same Filename already exists")
	}
	_, ok = userdata.ReceivedFiles[filename]
	if ok {
		return errors.New("File with Same Filename already exists")
	}
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "_VK")
	if !ok {
		return errors.New("Sender Verification Key Not in KeyStore")
	}
	var invitationHMAC InvitationHMAC
	invitationHMACBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Invitation Does Not Exist")
	}
	err := json.Unmarshal(invitationHMACBytes, &invitationHMAC)
	if err != nil {
		return err
	}
	err = userlib.DSVerify(verifyKey, invitationHMAC.Invitation, invitationHMAC.Signature)
	if err != nil {
		return errors.New("Invitation Authentication Failed")
	}
	HMACForInvitation, err := userlib.HMACEval(invitationHMAC.HMACInvitationKey, invitationHMAC.Invitation)
	if err != nil {
		return err
	}
	sameHMAC := userlib.HMACEqual(HMACForInvitation, invitationHMAC.HMACInvitation)
	if !sameHMAC {
		return errors.New("Invitation HMAC may be tampered")
	}

	userdata.ReceivedFiles[filename] = invitationPtr
	userdata.UpdateMaps(userdata.CreatorMap, userdata.ReceivedFiles)
	UpdateUser(userdata)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	userdata = GetUpatedUser(userdata)
	//check if you are owner
	sourceKey, ok := userdata.CreatorMap[filename]
	if !ok {
		return errors.New("You are not owner")
	}
	//check if recipient is recipient
	_, ok = userdata.CreatedFiles[filename][recipientUsername]
	if !ok {
		return errors.New("User you are trying to revoke does not have access to file")
	}

	// remove recipient from map
	delete(userdata.CreatedFiles[filename], recipientUsername)
	UpdateUser(userdata)

	//change uuid of file struct and all ciphertext structs to random uuid
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return errors.New("Error loading Content")
	}
	storageKey, err := uuid.FromBytes(sourceKey)
	if err != nil {
		return err
	}
	//Discard File Struct
	userlib.DatastoreDelete(storageKey)
	//Act as if we didnt have file so we can generate new uuids
	delete(userdata.CreatorMap, filename)
	err = userdata.UpdateMaps(userdata.CreatorMap, userdata.ReceivedFiles)
	if err != nil {
		return err
	}
	UpdateUser(userdata)
	invitationMap := userdata.CreatedFiles[filename]
	err = userdata.StoreFile(filename, content)

	if err != nil {
		return errors.New("Error storing Content")
	}

	userdata = GetUpatedUser(userdata)
	//creatorMap, err = userdata.GetCreatorMap()
	//if err != nil {
	//	return err
	//}
	//This is new file source key
	newSourceKey, ok := userdata.CreatorMap[filename]
	if !ok {
		return errors.New("File Lost during Revoke")
	}

	for recipient, invitationHMACUUID := range invitationMap {
		print(recipient)
		var invitation Invitation
		var invitationHMAC InvitationHMAC

		recipientPK, ok := userlib.KeystoreGet(recipient + "_PK")
		if !ok {
			return errors.New("Recipient Error")
		}
		invitationHMACBytes, ok := userlib.DatastoreGet(invitationHMACUUID)
		if !ok {
			return errors.New("Recipient Error")
		}

		err := json.Unmarshal(invitationHMACBytes, &invitationHMAC)
		if err != nil {
			return err
		}

		//HMAC Check for InvitationHMAC
		HMACForInvitationHMAC, err := userlib.HMACEval(invitationHMAC.HMACInvitationKey, invitationHMAC.Invitation)
		if err != nil {
			return err
		}
		sameHMAC := userlib.HMACEqual(HMACForInvitationHMAC, invitationHMAC.HMACInvitation)
		if !sameHMAC {
			return errors.New("Recipient's Invitation HMAC may be tampered")
		}

		//Retrieve Invitation Struct
		err = json.Unmarshal(invitationHMAC.Invitation, &invitation)
		if err != nil {
			return err
		}

		//HMAC Check for Invitation
		HMACForEncryptedSourceKey, err := userlib.HMACEval(invitation.HMACEncryptedSourceKeyKey, invitation.EncryptedSourceKey)
		if err != nil {
			return err
		}
		sameHMACforInvitation := userlib.HMACEqual(HMACForEncryptedSourceKey, invitation.HMACEncryptedSourceKey)
		if !sameHMACforInvitation {
			return errors.New("Recipient's Invitation may be tampered")
		}

		//Retrieve Source Key
		newEncryptedSourceKey, err := userlib.PKEEnc(recipientPK, newSourceKey)
		if err != nil {
			return err
		}

		invitation.EncryptedSourceKey = newEncryptedSourceKey

		//HMAC Encrypted Source Key
		soureKeyHMACKey := userlib.RandomBytes(16)
		sourceKeyHMAC, err := userlib.HMACEval(soureKeyHMACKey, invitation.EncryptedSourceKey)
		if err != nil {
			return err
		}
		invitation.HMACEncryptedSourceKeyKey = soureKeyHMACKey
		invitation.HMACEncryptedSourceKey = sourceKeyHMAC

		newInvitationBytes, err := json.Marshal(invitation)
		if err != nil {
			return err
		}

		newSignature, err := userlib.DSSign(userdata.SignKey, newInvitationBytes)
		if err != nil {
			return err
		}
		invitationHMAC.Invitation = newInvitationBytes
		invitationHMAC.Signature = newSignature

		//HMAC Invitation
		newInvitationHMACKey := userlib.RandomBytes(16)
		newInvitationStructHMAC, err := userlib.HMACEval(newInvitationHMACKey, invitationHMAC.Invitation)
		if err != nil {
			return err
		}
		invitationHMAC.HMACInvitation = newInvitationStructHMAC
		invitationHMAC.HMACInvitationKey = newInvitationHMACKey

		//Store InvitationHMAC Struct into DataStore
		newInvitationHMACBytes, err := json.Marshal(invitationHMAC)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(invitationHMACUUID, newInvitationHMACBytes)

	}
	UpdateUser(userdata)
	return nil
}

func GetUpatedUser(oldUser *User) (updatedUser *User) {
	user, _ := GetUser(oldUser.Username, oldUser.Password)
	return user
}
