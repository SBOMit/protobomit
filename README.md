# Protobomit  
   
Protobomit is a command line tool designed to manage Software Bill of Materials (SBOM) by adding in-toto attestations as an external references.  
   
## Features  
   
- Generate a new SBOM with associated attestations  
- Verify SBOM provenance
- Add in-toto attestations as external references to SBOMs  
- Support for CycloneDX and SPDX SBOM formats  
   
## Installation  
   
To install protobomit, you need to have Go installed on your machine. You can download it from the official [Go Downloads](https://golang.org/dl/) page.  
   
Once Go is installed, you can install Protobomit by running:  
   
```bash  
go get github.com/testifysec/protobomit  
```  
   
## Usage  
   
To generate a new SBOM with associated attestations:  
   
```bash  
./protobomit generate --sbom <path-to-sbom> --attestation <path-to-attestation> --policy <path-to-policy> --publicKey <path-to-public-key>  
```  
   
## Development  
   
To contribute to the development of Protobomit, you can clone the repository:  
   
```bash  
git clone https://github.com/testifysec/protobomit.git  
```  
   
Navigate to the cloned repository:  
   
```bash  
cd protobomit  
```  
   
Run tests:  
   
```bash  
go test ./...  
```  
   
## License  
   
Protobomit is licensed under [Apache 2.0]](LICENSE).  
   
## Contributing  
   
Contributions are welcome.
   
## Contact  
   
For any inquiries or issues, please open an issue on the [Protobomit GitHub repository](https://github.com/testifysec/protobomit/issues).