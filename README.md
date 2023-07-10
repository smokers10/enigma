# Enigma
An encryption tool to create confidential config value for infrast package

## How To Use
### Step 1 : Create Confidential File
create a YAML file named "confidentials.yaml" on main directory.
### Step 2 : Set Your Confidentials Data
here the example of confidentials YAML file : 
```
key : your-encryption-key // use 16, 24 or 32 length string to select either AES-128, AES-192 or Aes-256
confidentials :
  - label : application secret
    value : your-application-secret
  - label : postgres password
    value : your-postgres-password
  - label : mongo uri
    value : your-mongo-uri
  - label : smtp password
    value : your-smtp-password
  - label : midtrans server key
    value : your-midtrans-server-key
```
### Step 3 : Run enigma
run enigma by this command :
```
go run main.go
```
