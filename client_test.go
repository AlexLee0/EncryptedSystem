package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobLaptop *client.User

	var charlesLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Edge Cases for InitUser", func() {
		Specify("Edge Case: Testing InitUser errors when user with same username exists.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with same username as Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge Case: Testing InitUser errors on empty username.", func() {
			userlib.DebugMsg("Initializing an empty user.")
			bob, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Edge Cases for GetUser", func() {
		Specify("Edge Case: Testing GetUser errors when there is no initialized user for the given username.", func() {
			userlib.DebugMsg("Get user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("Edge Case: Testing GetUser errors when the user credentials are invalid.", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get user Alice.")
			aliceLaptop, err = client.GetUser("alice", contentOne)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Unit test for Store/Load for creator", func() {
		Specify("Unit Test: Store/Load for creator", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

		})

	})

	Describe("Edge cases for File Operations", func() {
		Specify("The given filename does not exist in the personal file namespace of the caller.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Appending file...")
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Edge cases for Share Operations", func() {
		Specify("Create Invitation Edge Cases", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating Invitation...")
			_, err := alice.CreateInvitation("aliceFile", "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Creating Invitation...")
			_, err = alice.CreateInvitation("aliceFile", "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Share Invitation Edge Cases", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", aliceFile, contentTwo)
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating Invitation...")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accepting Invitation...")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Edge cases for Revoke Operations", func() {
		Specify("The given filename does not exist in the personal file namespace of the caller.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating Invitation...")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accepting Invitation...")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", bobFile)
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking Charles's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Unit tests for Create/Accept", func() {
		Specify("Basic Test: Create/Accept without Append", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob is Loading file...")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("aliceLaptop creating invite for Charlie.")
			_, err = aliceLaptop.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			// userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", charlesFile)
			// err = charles.AcceptInvitation("alice", invite1, charlesFile)
			// Expect(err).To(BeNil())

			userlib.DebugMsg("Charles is Loading file...")
			data1, err := charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			Expect(data1).ToNot(Equal([]byte(contentOne)))
		})

		Specify("Basic Test: Create/Accept with Append", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob is Loading file...")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice is Loading file...")
			data1, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Bob is Loading file...")
			data2, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})
	})

	Describe("Tests for revoke", func() {
		Specify("Test if non-revoked users are affected after revoke", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice is Loading file...")
			data1, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob is Loading file...")
			data2, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Alice creating invite for Charles.")
			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from Alice under filename %s.", charlesFile)
			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob should have no access to %s.", aliceFile)
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles should still have access.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())

		})

		Specify("Test if children of revoked users are affected after revoke", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bobLaptop.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			data1, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			err = bobLaptop.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data2, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			data3, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			charlesLaptop, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			invite1, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charlesLaptop.AcceptInvitation("bob", invite1, charlesFile)
			Expect(err).To(BeNil())

			err = charlesLaptop.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data4, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data4).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))

			data5, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data5).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))

			data6, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data6).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))

			err = bobLaptop.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data7, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data7).To(Equal([]byte(contentOne)))

			data8, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data8).To(Equal([]byte(contentOne)))

			data9, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data9).To(Equal([]byte(contentOne)))

			err = charles.StoreFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data10, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data10).To(Equal([]byte(contentTwo)))

			data11, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data11).To(Equal([]byte(contentTwo)))

			data12, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data12).To(Equal([]byte(contentTwo)))

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			data13, err := bobLaptop.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data13).ToNot(Equal([]byte(contentTwo)))

			data14, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			Expect(data14).ToNot(Equal([]byte(contentTwo)))

			err = charlesLaptop.AppendToFile(charlesFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			err = bobLaptop.AppendToFile(charlesFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Test for random errors", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal([]byte(contentOne + contentTwo + contentThree)))

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			_, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bobLaptop.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			err = bobLaptop.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			data1, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			err = bobLaptop.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data2, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			data3, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			charlesLaptop, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			invite1, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charlesLaptop.AcceptInvitation("bob", invite1, charlesFile)
			Expect(err).To(BeNil())

			err = charlesLaptop.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data4, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data4).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))

			data5, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data5).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))

			data6, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data6).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne + contentTwo)))

			err = bobLaptop.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data7, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data7).To(Equal([]byte(contentOne)))

			data8, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data8).To(Equal([]byte(contentOne)))

			data9, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data9).To(Equal([]byte(contentOne)))

			err = charles.StoreFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data10, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data10).To(Equal([]byte(contentTwo)))

			data11, err := bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data11).To(Equal([]byte(contentTwo)))

			data12, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data12).To(Equal([]byte(contentTwo)))

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			data13, err := bobLaptop.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data13).ToNot(Equal([]byte(contentTwo)))

			data14, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			Expect(data14).ToNot(Equal([]byte(contentTwo)))

			err = charlesLaptop.AppendToFile(charlesFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			err = bobLaptop.AppendToFile(charlesFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Bandwidth Test", func() {
		Specify("Test if # of appends scales", func() {
			print(userlib.DatastoreGetBandwidth())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			initial := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile, []byte(contentTwo))
			after := userlib.DatastoreGetBandwidth()
			Expect(after - initial).To(BeNumerically("~", len([]byte(contentTwo)), 2000))
			print(after - initial)
		})
	})

})
