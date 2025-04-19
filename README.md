# IBM Verify SDK for Go

IBM Verify solves hybrid challenges with secure, frictionless IAM that simplifies identity and strengthens your identity fabric—without burdening admins. Learn more about [IBM Verify here](https://ibm.com/verify) and sign up for a free SaaS tenant.

IBM Verify SDK for Go offers various packages to leverage IBM Verify SaaS and can be embedded in other Go applications to build automated toolchains and applications. These packages are also used by the [IBM Verify CLI](https://github.com/ibm-verify/verifyctl).

## Getting started

[Go](https://golang.org) is required to develop using the SDK. This SDK is a collection of various packages:

1. [Authentication](pkg/auth): Offers a set of modules to authenticate with IBM Verify using OAuth 2.0 and OpenID Connect 1.0 flows.

## Release management

The SDK is published in the form of Github releases that can be natively referenced in your go.mod file. Note that breaking changes will be part of the changelog and is only comparable to the previous release version. In general, a breaking change will result in a new major version.
