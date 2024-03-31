AES-128 is a version of the Advanced Encryption Standard (AES) that uses a 128-bit key for encryption and decryption. It is part of the AES family of encryption algorithms, which also includes AES-192 and AES-256, referring to the key length used in each variant. Here's an overview of AES-128:

### Key Features
- **Key Length**: 128 bits, providing a good balance between security and performance.
- **Block Size**: 128 bits, meaning that the data is divided into blocks of 128 bits each for encryption and decryption processes.
- **Rounds of Encryption**: 10 rounds of a specific set of operations that include substitution, permutation, mixing, and key addition.

### Security
AES-128 is considered secure against all known practical attacks when properly implemented and used. It has been widely analyzed and is the standard choice for many applications needing cryptographic security.

### Usage
- **Data Encryption**: Commonly used in software and hardware to encrypt sensitive data.
- **Secure Communication**: Forms the basis of many protocols like SSL/TLS for secure web browsing.
- **File Encryption**: Used in various file encryption standards and tools.

### Advantages
- **Efficiency**: Operates efficiently in various computing environments, from small microcontrollers to large servers.
- **Standardization**: AES-128 is an international standard, ensuring broad compatibility and support.
- **Flexibility**: Can be used in various modes of operation, like CBC (Cipher Block Chaining), GCM (Galois/Counter Mode), and others, providing versatility in addressing different security requirements.

In conclusion, AES-128 is a widely trusted and used symmetric encryption standard, providing strong security and high performance for encrypting data.

![image](https://github.com/Lin-Yu-Ming/AES-128-Encryption/assets/71814265/7e7f1d0b-2e4c-40fd-8ed6-fd606e301fe0)


• I/O information


![image](https://github.com/Lin-Yu-Ming/AES-128-Encryption/assets/71814265/e16fc8f8-3662-4b99-b6c8-75f7dc92d435)

• AES flow diagram:
A total of 10 rounds are performed, with no MixColumns transformation required in the final round.
The Round 0 key is a secret key sent through the I/O port “key”, while the other round keys are computed through the 
key expansion operation.

![image](https://github.com/Lin-Yu-Ming/AES-128-Encryption/assets/71814265/0e66e31e-3f11-4104-8ecd-6c05dea05b95)


•FSM


![image](https://github.com/Lin-Yu-Ming/AES-128-Encryption/assets/71814265/59ee1921-d2c1-450e-a7ee-d05b3ad510ac)



