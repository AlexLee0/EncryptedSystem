# End-to-End Encrypted File Sharing System
This system allows verified users to share arbitrarily large files utilizing a client through an insecure data server. Our implementation ensures attacks to recover revoked files, silently tamper data, and impersonate users are computationally infeasible.

For comprehensive documentation, see the Project 2 Spec (https://cs161.org/proj2/).

Our implementation is written in `client/client.go` and the integration/unit tests in `client_test/client_test.go` and `client/client_unittest.go`.

To test the implementation, run `go test -v` inside of the `client_test` directory. This will run all tests in both `client/client_unittest.go` and `client_test/client_test.go`.
