#ifndef SIMECK64_H
#define SIMECK64_H

#include <immintrin.h> // AVX2 SIMD
#include <stdint.h>


//AVX-2 SIMD
typedef __m256i	REGISTER;
#define LOAD(x)			_mm256_loadu_si256((REGISTER*)x)
#define STORE(x,y)		_mm256_storeu_si256((REGISTER*)x,y)
#define SET32(a)		_mm256_set1_epi32(a)
#define XOR(x,y)		_mm256_xor_si256(x,y)
#define OR(x,y)			_mm256_or_si256(x,y)
#define AND(x,y)		_mm256_and_si256(x,y)

#define SHIFT32_L(x,r)	_mm256_slli_epi32(x,r)
#define SHIFT32_R(x,r)	_mm256_srli_epi32(x,r)
#define ROT32_L(x,r)	OR(SHIFT32_L(x,r),SHIFT32_R(x,32-r))

#define ROT32_L5(x)	OR(SHIFT32_L(x,5),SHIFT32_R(x,27))
#define ROT32_L1(x)	OR(SHIFT32_L(x,1),SHIFT32_R(x,31))

#define ROT32_R(x,r)	OR(SHIFT32_R(x,r),SHIFT32_L(x,32-r))


void simeck64_128_Enc_SIMD_8blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD
    __m256i data1, data2, data3, data4;

	data1 = LOAD(&plaintext[0]); // right1
	data2 = LOAD(&plaintext[8]); // left1


	for(i=0; i<44; i++){
		// ROL5(left)
		data3 = ROT32_L5(data2);

		// ROL5(left) & left
		data4 = AND(data3, data2);
		
		// right = right ^ (ROL5(left) & left)
		data1 = XOR(data1, data4);

		// ROL1(left)
		data3 = ROT32_L1(data2);

		// right = (right ^ (ROL5(left) & left)) ^ ROL1(left)
		data1 = XOR(data1, data3);

		// Load Roundkey(rk)
		data4 = SET32(key[i]);

		//Backup Left
		data3 = data2;

		// left = ((right ^ (ROL5(left) & left)) ^ ROL1(left)) ^ rk
		data2 = XOR(data1, data4);

		// right = left
		data1 = data3;

	}


	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
}

void simeck64_128_Enc_SIMD_16blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD
    __m256i data1, data2, data3, data4, data5, data6, data7, data8;
    __m256i data9, data10, data11, data12, data13, data14, data15, data16;


	data1 = LOAD(&plaintext[0]); // right1
	data2 = LOAD(&plaintext[8]); // left1

	data3 = LOAD(&plaintext[16]); // right2
	data4 = LOAD(&plaintext[24]); // left2

	for(i=0; i<44; i++){
		// ROL5(left)
		data5 = ROT32_L5(data2);
		data6 = ROT32_L5(data4);

		// ROL5(left) & left
		data7 = AND(data5, data2);
		data8 = AND(data6, data4);
		
		// right = right ^ (ROL5(left) & left)
		data1 = XOR(data1, data7);
		data3 = XOR(data3, data8);

		// ROL1(left)
		data7 = ROT32_L1(data2);
		data8 = ROT32_L1(data4);

		// right = (right ^ (ROL5(left) & left)) ^ ROL1(left)
		data1 = XOR(data1, data8);
		data3 = XOR(data3, data8);

		// Load Roundkey(rk)
		data7 = SET32(key[i]);

		//Backup Left
		data9 = data5;
		data10 = data6;

		// left = ((right ^ (ROL5(left) & left)) ^ ROL1(left)) ^ rk
		data2 = XOR(data1, data7);
		data4 = XOR(data3, data7);

		// right = left
		data1 = data5;
		data3 = data6;
	}


	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit

}

void simeck64_128_Enc_SIMD_24blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD
    __m256i data1, data2, data3, data4, data5, data6, data7, data8;
    __m256i data9, data10, data11, data12;


	data1 = LOAD(&plaintext[0]); // right1
	data2 = LOAD(&plaintext[8]); // left1

	data3 = LOAD(&plaintext[16]); // right2
	data4 = LOAD(&plaintext[24]); // left2

	data5 = LOAD(&plaintext[32]); //right3
	data6 = LOAD(&plaintext[40]); //left3

	for(i=0; i<44; i++){
		// ROL5(left)
		data7 = ROT32_L5(data2);
		data8 = ROT32_L5(data4);
		data9 = ROT32_L5(data6);

		// ROL5(left) & left
		data10 = AND(data7, data2);
		data11 = AND(data8, data4);
		data12 = AND(data9, data6);
		
		// right = right ^ (ROL5(left) & left)
		data1 = XOR(data1, data10);
		data3 = XOR(data3, data11);
		data5 = XOR(data5, data12);

		// ROL1(left)
		data7 = ROT32_L1(data2);
		data8 = ROT32_L1(data4);
		data9 = ROT32_L1(data6);

		// right = (right ^ (ROL5(left) & left)) ^ ROL1(left)
		data1 = XOR(data1, data7);
		data3 = XOR(data3, data8);
		data5 = XOR(data5, data9);

		// Load Roundkey(rk)
		data10 = SET32(key[i]);

		//Backup Left
		data7 = data2;
		data8 = data4;
		data9 = data6;

		// left = ((right ^ (ROL5(left) & left)) ^ ROL1(left)) ^ rk
		data2 = XOR(data1, data10);
		data4 = XOR(data3, data10);
		data6 = XOR(data5, data10);

		// right = left
		data1 = data7;
		data3 = data8;
		data5 = data9;
	}


	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit
	STORE(&ciphertext[32], data5);//256-bit
	STORE(&ciphertext[40], data6);//256-bit
}

void simeck64_128_Enc_SIMD_32blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD
    __m256i data1, data2, data3, data4, data5, data6, data7, data8;
    __m256i data9, data10, data11, data12, data13, data14, data15, data16;

	data1 = LOAD(&plaintext[0]); // right1
	data2 = LOAD(&plaintext[8]); // left1

	data3 = LOAD(&plaintext[16]); // right2
	data4 = LOAD(&plaintext[24]); // left2

	data5 = LOAD(&plaintext[32]); //right3
	data6 = LOAD(&plaintext[40]); //left3

	data7 = LOAD(&plaintext[48]); //right4
	data8 = LOAD(&plaintext[56]); //left4

	for(i=0; i<44; i++){
		// ROL5(left)
		data9 = ROT32_L5(data2);
		data10 = ROT32_L5(data4);
		data11 = ROT32_L5(data6);
		data12 = ROT32_L5(data8);

		// ROL5(left) & left
		data13 = AND(data9, data2);
		data14 = AND(data10, data4);
		data15 = AND(data11, data6);
		data16 = AND(data12, data8);
		
		// right = right ^ (ROL5(left) & left)
		data1 = XOR(data1, data13);
		data3 = XOR(data3, data14);
		data5 = XOR(data5, data15);
		data7 = XOR(data7, data16);

		// ROL1(left)
		data9 = ROT32_L1(data2);
		data10 = ROT32_L1(data4);
		data11 = ROT32_L1(data6);
		data12 = ROT32_L1(data8);

		// right = (right ^ (ROL5(left) & left)) ^ ROL1(left)
		data1 = XOR(data1, data9);
		data3 = XOR(data3, data10);
		data5 = XOR(data5, data11);
		data7 = XOR(data7, data12);

		// Load Roundkey(rk)
		data16 = SET32(key[i]);

		//Backup Left
		data9 = data2;
		data10 = data4;
		data11 = data6;
		data12 = data8;

		// left = ((right ^ (ROL5(left) & left)) ^ ROL1(left)) ^ rk
		data2 = XOR(data1, data16);
		data4 = XOR(data3, data16);
		data6 = XOR(data5, data16);
		data8 = XOR(data7, data16);

		// right = left
		data1 = data9;
		data3 = data10;
		data5 = data11;
		data7 = data12;
	}


	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit
	STORE(&ciphertext[32], data5);//256-bit
	STORE(&ciphertext[40], data6);//256-bit
	STORE(&ciphertext[48], data7);//256-bit
	STORE(&ciphertext[56], data8);//256-bit
}



#endif  // SIMECK64_H
