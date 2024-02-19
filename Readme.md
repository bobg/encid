# Encid - encode and decode encrypted integer IDs

[![Go Reference](https://pkg.go.dev/badge/github.com/bobg/encid.svg)](https://pkg.go.dev/github.com/bobg/encid)
[![Go Report Card](https://goreportcard.com/badge/github.com/bobg/encid)](https://goreportcard.com/report/github.com/bobg/encid)
[![Tests](https://github.com/bobg/encid/actions/workflows/go.yml/badge.svg)](https://github.com/bobg/encid/actions/workflows/go.yml)
[![Coverage Status](https://coveralls.io/repos/github/bobg/encid/badge.svg?branch=master)](https://coveralls.io/github/bobg/encid?branch=master)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

This is encid,
a program and library for working with encrypted integer IDs.

The main use case is when you have a database
that assigns consecutive integer IDs to resources
and you need to expose them publicly
without revealing the actual values.

For example,
suppose you have a web-based service
that handles URLs of the form
https://example.com/profile?user=17
for showing the profile page of a user.
This URL allows an attacker to guess other valid profile URLs
(e.g., https://example.com/profile?user=1, https://example.com/profile?user=2, etc.),
reveals that this user is probably the 17th one to have signed up,
suggests a possible relationship between users with ids close to each other,
and via scraping can expose your total number of users
(e.g., if there’s no https://example.com/profile?user=18,
you’ve probably got only 17 users).

On the other hand,
if your service’s profile URLs look like
https://example.com/profile?user=7pWwPc2rWTzsZX85s9KFgRW,
there is no way for an attacker to guess that the consecutively next profile URL is
https://example.com/profile?user=bgnnCXYybm7q5FshMN4xYRT
or to tell how close or far apart they are
or to scrape all your profile URLs
or to know how many users you have.

## Installation and usage

For library usage please see
[the Godoc](https://pkg.go.dev/github.com/bobg/encid).

To install the CLI:

```sh
go install github.com/bobg/encid/cmd/encid@latest
```

Command-line usage:

```sh
encid [-keystore FILE] enc [-50] TYPE NUM
encid [-keystore FILE] dec [-50] ID STR
encid [-keystore FILE] newkey TYPE
```

The `-keystore` flag specifies the path to a database containing cipher keys for encrypting and decrypting IDs.
By default this lives under the `encid` directory in [os.UserConfigDir()](https://pkg.go.dev/os#UserConfigDir).

Each cipher key is associated with an integer “type” whose meanings are user-defined.
You may choose to give all your keys the same type,
or you might prefer to use different types for different resources
(e.g. 1 for users, 2 for documents, etc).

In `enc` mode,
you specify a type and a number to encode.
You get back a “key ID” and the encoded string.
The latest cipher key for the given type is used.
If no cipher key exists in the keystore for the given type,
one is created.

```sh
$ encid enc 1 17
4 d7w90xn4pfk9rfqw9d4wc0zdn0
```

In `dec` mode,
you specify a key ID and an encoded string.
You get back a type and the decoded number.

```sh
$ encid dec 4 d7w90xn4pfk9rfqw9d4wc0zdn0
1 17
```

In `newkey` mode,
you specify a type.
A new random cipher key with that type
is added to the keystore.

The encoding uses base 30 by default.
The `-50` flag causes base 50 to be used instead.
For more information about these encodings
please see [basexx](https://pkg.go.dev/github.com/bobg/basexx/v2#pkg-variables).
