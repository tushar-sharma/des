/*
    Purpose                 : Implementing DES (Only for learning purposes)

    Input                   : 64 bits of plaintext message in ascii
                              64 bits of plaintext key in ascii
    Output                  : 64 bits of base64 cipher 
                              64 bits of plaintex message in ascci recovered
    Author                  : Tushar Sharma
 */
#include <iostream>
#include <cstring> 
#include <cstdlib> 
using namespace std;

#define B64(_)					\
  ((_) == 'A' ? 0				\
   : (_) == 'B' ? 1				\
   : (_) == 'C' ? 2				\
   : (_) == 'D' ? 3				\
   : (_) == 'E' ? 4				\
   : (_) == 'F' ? 5				\
   : (_) == 'G' ? 6				\
   : (_) == 'H' ? 7				\
   : (_) == 'I' ? 8				\
   : (_) == 'J' ? 9				\
   : (_) == 'K' ? 10				\
   : (_) == 'L' ? 11				\
   : (_) == 'M' ? 12				\
   : (_) == 'N' ? 13				\
   : (_) == 'O' ? 14				\
   : (_) == 'P' ? 15				\
   : (_) == 'Q' ? 16				\
   : (_) == 'R' ? 17				\
   : (_) == 'S' ? 18				\
   : (_) == 'T' ? 19				\
   : (_) == 'U' ? 20				\
   : (_) == 'V' ? 21				\
   : (_) == 'W' ? 22				\
   : (_) == 'X' ? 23				\
   : (_) == 'Y' ? 24				\
   : (_) == 'Z' ? 25				\
   : (_) == 'a' ? 26				\
   : (_) == 'b' ? 27				\
   : (_) == 'c' ? 28				\
   : (_) == 'd' ? 29				\
   : (_) == 'e' ? 30				\
   : (_) == 'f' ? 31				\
   : (_) == 'g' ? 32				\
   : (_) == 'h' ? 33				\
   : (_) == 'i' ? 34				\
   : (_) == 'j' ? 35				\
   : (_) == 'k' ? 36				\
   : (_) == 'l' ? 37				\
   : (_) == 'm' ? 38				\
   : (_) == 'n' ? 39				\
   : (_) == 'o' ? 40				\
   : (_) == 'p' ? 41				\
   : (_) == 'q' ? 42				\
   : (_) == 'r' ? 43				\
   : (_) == 's' ? 44				\
   : (_) == 't' ? 45				\
   : (_) == 'u' ? 46				\
   : (_) == 'v' ? 47				\
   : (_) == 'w' ? 48				\
   : (_) == 'x' ? 49				\
   : (_) == 'y' ? 50				\
   : (_) == 'z' ? 51				\
   : (_) == '0' ? 52				\
   : (_) == '1' ? 53				\
   : (_) == '2' ? 54				\
   : (_) == '3' ? 55				\
   : (_) == '4' ? 56				\
   : (_) == '5' ? 57				\
   : (_) == '6' ? 58				\
   : (_) == '7' ? 59				\
   : (_) == '8' ? 60				\
   : (_) == '9' ? 61				\
   : (_) == '+' ? 62				\
   : (_) == '/' ? 63				\
   : -1)


template <class T>
void reverse(T arrayString[], size_t len)                        //Reverse generic array
{
    for (int i = 0; i < (len) / 2; i++) {
        //swapping values
        arrayString[i] ^= arrayString[len -i -1];                // a = a xor b
        arrayString[len -i -1] ^= arrayString[i];                // b = a xor b
        arrayString[i] ^= arrayString[len -i -1];                // a = a xor b
    }
}

void btob64 (const int *ip, int len, char *str)
{
    char base64s[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   
    int factor = 32, num = 0, index = 0, arr[12] = {0}; 

    for (size_t i = 0; i < len; i++)
     {
       num = num + (ip[i] * factor);
          if (i % 6 == 5) {
           arr[index++] =  num;
           num = 0;
           factor = 32;
       }
       else {
           factor = factor / 2;
       }
    }

   arr[index] = num;

  for (size_t i = 0; i < 11; i++) {
       str[i] = base64s[arr[i]];
       index = i;
   }

   int pad = 6 - (64 % 6);

   while (pad > 1) {
       str[++index] = '=';
       pad = pad / 2;
   }

}

void encode (const int *bmsgptr, int *ipptr, int key[][48], char *cmsg, int flag)   //Generates cipher text 
{
    int factor = 128;

    int IP[8][8] = { {58, 50, 42, 34, 26, 18, 10, 2}, 
                     {60, 52, 44, 36, 28, 20, 12, 4}, 
                     {62, 54, 46, 38, 30, 22, 14, 6}, 
                     {64, 56, 48, 40, 32, 24, 16, 8}, 
                     {57, 49, 41, 33, 25, 17, 9, 1}, 
                     {59, 51, 43, 35, 27, 19, 11, 3}, 
                     {61, 53, 45, 37, 29, 21, 13, 5}, 
                     {63, 55, 47, 39, 31, 23, 15, 7} }; 

    int E[8][6] = { {32, 1, 2, 3, 4, 5}, 
                    {4, 5, 6, 7, 8, 9}, 
                    {8, 9, 10, 11, 12, 13}, 
                    {12, 13, 14, 15, 16, 17}, 
                    {16, 17, 18, 19, 20, 21}, 
                    {20, 21, 22, 23, 24, 25}, 
                    {24, 25, 26, 27, 28, 29},
                    {28, 29, 30, 31, 32, 1} };
 
    int S[32][16] = { {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},    //1st
                      {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, 
                      {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, 
                      {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},   
                      {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},    //2nd
                      {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, 
                      {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, 
                      {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}, 
                      {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},     //3rd
                      {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, 
                      {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, 
                      {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}, 
                      {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},     //4th
                      {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, 
                      {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, 
                      {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
                      {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},     //5th
                      {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, 
                      {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, 
                      {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}, 
                      {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},    //6th
                      {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, 
                      {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, 
                      {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}, 
                      {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},    //7th 
                      {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, 
                      {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, 
                      {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}, 
                      {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},    //8th
                      {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, 
                      {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, 
                      {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11} }; 

    int P[8][4] = { {16, 7, 20, 21}, 
                    {29, 12, 28, 17}, 
                    {1, 15, 23, 26}, 
                    {5, 18, 31, 10}, 
                    {2, 8, 24, 14}, 
                    {32, 27, 3, 9}, 
                    {19, 13, 30, 6}, 
                    {22, 11, 4, 25} }; 

    int IPinv[8][8] = { {40, 8, 48, 16, 56, 24, 64, 32}, 
                        {39, 7, 47 ,15, 55, 23, 63, 31}, 
                        {38, 6, 46, 14, 54, 22, 62, 30}, 
                        {37, 5, 45, 13, 53, 21, 61, 29},
                        {36, 4, 44, 12, 52, 20, 60, 28},
                        {35, 3, 43, 11, 51, 19, 59, 27}, 
                        {34, 2, 42, 10, 50, 18, 58, 26}, 
                        {33, 1, 41, 9, 49, 17, 57, 25} };

    int rlsum[64] = {0}, rlsum_new[64] = {0};

    int index, row, col, num, index1 = 0;
    int er[48] = {0};
    int foo[4] = {0}; 
    int l[17][32] = {0};                                                 //Ln
    int r[17][32] = {0};                                                 //Rn
    int f[32] = {0}, f_new[32] = {0},  extra = 0, mark, count ;
 
    index = 0;
    for (int i = 0; i < 8; i++) {                                        //creating ip
        for (int j = 0; j < 8; j++) {
            ipptr[index++] = bmsgptr[IP[i][j] - 1];
        }
    }
    cout<<"\nIP\n"; 
    for (int i = 0; i < 64; i++) {
        cout<<ipptr[i]; 
    }
    
    for (int i = 0; i < 32; i++) {
        l[0][i] = ipptr[i]; 
    }

    for (int i = 32; i < 64; i++) {
        r[0][i - 32] = ipptr[i]; 
    } 
   
/****************/
    for (int i = 1; i < 17; i++) { 
        for (int j = 0; j < 32; j++) {
            l[i][j] = r[i - 1][j];
        }       //ln = Rn-1

        //calculate er
        index = 0; 
    
        for (int j = 0; j < 8; j++) {
            for (int k = 0; k < 6; k++) {
                er[index++] = r[i - 1][E[j][k] - 1];
            }
        }

        //calculate er =  er xor kn
        if (flag == 0) {
            for (int j = 0; j < 48; j++) {
                er[j] ^= key[i-1][j];
            } 
        }
        else if (flag == 1){
             for (int j = 0; j < 48; j++) {
                er[j] ^= key[16 - i][j];
            } 

        }
  
        
        //index1 = 0;
        row = 0, col = 0; 
        mark = 0; 
         
        index1 = 0, extra = 0;

        while (mark < 48) {
            index = 0;
            row = (er[mark] *2) + er[mark + 5]; 
            col = (8 * er[mark + 1]) + (4 * er[mark + 2]) + (2 * er[mark + 3]) + er[mark + 4]; 
       
            num = S[row + extra][col]; 
             
            count = 0; 
            while (num > 0) { 
               count++;
               foo[index++] = num % 2; 
               num = num / 2;
            }

            while ((count++) < 4){
               foo[index++] = 0;    
            }

            reverse <int> (foo, sizeof foo / sizeof foo[0]);

            mark = mark + 6; 

            for (int k = 0; k < 4; k++) {
                f[index1++] = foo[k]; 
            }
            extra = extra + 4;
        }
        
    index = 0; 
    for (int j = 0; j < 8; j++){ 
        for (int k = 0; k < 4; k++) {
            f_new[index++] = f[P[j][k] - 1]; 
        }
    }

    for (int j = 0; j < 32; j++) {
        r[i][j] = l[i - 1][j] ^ f_new[j];
    }
} // for 16 times

    for (int i = 0; i < 32; i++) {
        rlsum[i] = r[16][i];
    }
    for (int i = 32; i < 64; i++) {
        rlsum[i] = l[16][i - 32];
    }
    cout<<"\nR16L16 sum\n";
    for (int i = 0; i < 64; i++) {
        cout<<rlsum[i];
    }
    index = 0;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            rlsum_new[index++] = rlsum[IPinv[i][j] - 1];  
        }
    }
    cout<<"\nIP inv \n";
    for (int i = 0; i < 64; i++) {
        cout<<rlsum_new[i];
    }
 
    cout<<endl;
    btob64 (rlsum_new, sizeof rlsum_new / sizeof rlsum_new[0], cmsg); 
   
} // encode function ends


void cal_keys_e (const int *ptr, size_t len, int keys[][48])                  //Generate sixteen 48 bits key
{

    int left_shift[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};


    int c[17][28] = {0};
    int d[17][28] = {0};
    int sum[16][56] = {0};
    int PC2[8][6] = { {14, 17, 11, 24, 1, 5},
                      {3, 28, 15, 6, 21, 10},
                      {23, 19, 12, 4, 26, 8},
                      {16, 7, 27, 20, 13, 2},
                      {41, 52, 31, 37, 47, 55},
                      {30, 40, 51, 45, 33, 48},
                      {44, 49, 39, 56, 34, 53},
                      {46, 42, 50, 36, 29, 32} };

    int i, j, carry1, carry2, index, k;


    for (i = 0; i < len / 2; i++) {                               //calculating c0
        c[0][i] = ptr[i];
    }

    for (i = len / 2; i < 56; i++) {                              //calculating d0
        d[0][i - 28] = ptr[i];
    }

    for (i = 1; i < 17; i++) {                                    // 16 rounds 
                                                                    
        for (j = 0; j < 28; j++) {                                //copying c0, d0 into c1, d1
            c[i][j] = c[i - 1][j]; 
            d[i][j] = d[i - 1][j]; 
        }

        while(left_shift[i - 1] != 0) {
            carry1 = c[i][0]; 
            carry2 = d[i][0];
 
            for (j = 0; j < 27; j++) {
                c[i][j] ^= c[i][j + 1]; 
                c[i][j + 1] ^= c[i][j]; 
                c[i][j] ^= c[i][j+1];

                d[i][j] ^= d[i][j + 1]; 
                d[i][j + 1] ^= d[i][j]; 
                d[i][j] ^= d[i][j + 1]; 
            }
            c[i][27] = carry1; 
            d[i][27] = carry2;
            left_shift[i - 1] -= 1; 
        } //end while

        for (j = 0; j < 28; j++) {

            sum[i - 1][j] = c[i][j]; 
        } 
    
        for (j = 28; j < 56; j++) {
            sum[i - 1][j] = d[i][j - 28]; 
        }
 
        index = 0; 

        for (j = 0; j < 8; j++) {
            for (k = 0; k < 6; k++) {
                keys[i - 1][index++] = sum[i - 1][PC2[j][k] - 1];
            }
        } 
    }
    


} //function ends

void cal_keys_d (const int *ptr, size_t len, int keys[][48])                   //Generate sixteen 48 bits key
{
    int right_shift[] = {0, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};



    int c[17][28] = {0};
    int d[17][28] = {0};
    int sum[16][56] = {0};
    int PC2[8][6] = { {14, 17, 11, 24, 1, 5},
                      {3, 28, 15, 6, 21, 10},
                      {23, 19, 12, 4, 26, 8},
                      {16, 7, 27, 20, 13, 2},
                      {41, 52, 31, 37, 47, 55},
                      {30, 40, 51, 45, 33, 48},
                      {44, 49, 39, 56, 34, 53},
                      {46, 42, 50, 36, 29, 32} };

    int i, j, carry1, carry2, index, k;


    for (i = 0; i < len / 2; i++) {                                       //calculating c0
        c[0][i] = ptr[i];
    }

    for (i = len / 2; i < 56; i++) {                                      //calculating d0
        d[0][i - 28] = ptr[i];
    }

    for (i = 1; i < 17; i++) {                                            // 16 rounds 
                                                                    
        for (j = 0; j < 28; j++) {                                        //copying c0, d0 into c1, d1
            c[i][j] = c[i - 1][j]; 
            d[i][j] = d[i - 1][j]; 
        }

        while(right_shift[i - 1] != 0) {
            carry1 = c[i][27]; 
            carry2 = d[i][27];
 
            for (j = 27; j >= 1; j--) {
                c[i][j] ^= c[i][j - 1]; 
                c[i][j - 1] ^= c[i][j]; 
                c[i][j] ^= c[i][j - 1];

                d[i][j] ^= d[i][j - 1]; 
                d[i][j - 1] ^= d[i][j]; 
                d[i][j] ^= d[i][j - 1]; 
            }
            c[i][0] = carry1; 
            d[i][0] = carry2;
            right_shift[i - 1] -= 1; 
        } //end while

        for (j = 0; j < 28; j++) {

            sum[i - 1][j] = c[i][j]; 
        } 
    
        for (j = 28; j < 56; j++) {
            sum[i - 1][j] = d[i][j - 28]; 
        }
 
        index = 0; 

        for (j = 0; j < 8; j++) {
            for (k = 0; k < 6; k++) {
                //keys[i - 1][index++] = sum[i - 1][PC2[j][k] - 1];
                keys[16 -i ][index++] = sum[i - 1][PC2[j][k] - 1];

            }
        } 
    }
    


} //function ends


void reduce_to_56 (const int *ptrKey, int *ptrKeyr)                            //reduce 64 bit key to 56 bit
{
int PC1[8][7] = {     {57, 49, 41, 33, 25, 17, 9},
                      {1, 58, 50, 42, 34, 26, 18},
                      {10, 2, 59, 51, 43, 35, 27},
                      {19, 11, 3, 60, 52, 44, 36},
                      {63, 55, 47, 39, 31, 23, 15},
                      {7, 62, 54, 46, 38, 30, 22},
                      {14, 6, 61, 53, 45, 37, 29},
                      {21, 13, 5, 28, 20, 12, 4} };

int index = 0; 

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 7; j++) {
            ptrKeyr[index++] = ptrKey[PC1[i][j] - 1];
        }
    }
}


void des (char msg[], int mlen, char key[], int klen, char *c, int flag) 
{
    int bmsg[64] = {0};                                                                            //Message in binary 64 bits
    int bkey[64] = {0};                                                                            //Key in binary 64 bits
    int bkeyr[56] = {0};                                                                           //Key in binary 56 bits
    int keys[16][48] = {0}; 	                                                                   //sixteen 48 bits keys
    int ip[64]  = {0}; 
    int index, bit_index;  
    char *temp;
    int arr1[12] = {0};

    if (flag == 0) {        //encryption
        index = 0;                                                                                     //initialization
        for (temp = msg; *temp; ++temp)                                                                //convert ascii message to binary
        {
            for (bit_index = sizeof (*temp) * 8 - 1; bit_index >= 0; --bit_index)
            {
               bmsg[index++] = (*temp >> bit_index) & 1; 
            }
        }
    } 
    else if (flag == 1) {

        size_t t = 0; 
        int cur, prev, digitsum;

        while ( t < strlen (msg)) {
            cur =  B64 (msg [t]); 

            if (cur != -1) {
                digitsum = t % 4; 

                switch (digitsum) 
                { 
                    case 0:
                    //do nothing
                        break;
                    case 1:
                        arr1[t] = (prev << 2) | (cur >> 4);
                        break;
                    case 2:
                        arr1[t] = ((prev & 0x0f) << 4) | (cur >> 2);  
                        break;
                    case 3:
                        arr1[t] = ((prev & 3) << 6) | (cur); 
                        break; 

                } 
            }
            prev = cur;
            ++t;  
        }

        index = 0;  
        for (size_t i = 0; i < 12; i++) {
            bit_index; 
            if (arr1[i] != 0) {
                for (bit_index = 7; bit_index >= 0; --bit_index) {
                   bmsg[index++] = (arr1[i] >> bit_index ) & 1; 
                } 
            }
        }

    }    //end decryption
        
    index = 0;                                                                                     //initialization
    for (temp = key; *temp; ++temp)                                                                //convert ascii key to binary
    {
        for (bit_index = sizeof (*temp) * 8 - 1; bit_index >= 0; --bit_index)
        {
            bkey[index++] = (*temp >> bit_index) & 1; 
        }
    }
  
    if (flag == 0) 
    cout<<"Message in ascii\n";
    else cout<<"Message in base64\n";
    for (size_t i = 0; i < mlen; i++) cout<<msg[i]; cout<<endl;
    cout<<"Message in binary\n";
    for (size_t i = 0; i < 64; i++) cout<<bmsg[i];  cout<<endl;
    cout<<"\nKey in ascii\n";
    for (size_t i = 0; i < klen; i++) cout<<key[i]; cout<<endl;
    cout<<"Key in binary\n";
    for (size_t i = 0; i < 64; i++) cout<<bkey[i];  cout<<endl;

    reduce_to_56 (bkey, bkeyr);                                                                     //function call
    cout<<"\n56 bit binary key \n";
    for (size_t i = 0; i < 56; i++) cout<<bkeyr[i]; cout<<endl;
  
    if (flag == 0)
        cal_keys_e (bkeyr, sizeof bkeyr / sizeof bkeyr[0], keys);                                        //function call
    else if (flag == 1)
        cal_keys_d (bkeyr, sizeof bkeyr / sizeof bkeyr[0], keys);                                        //function call

    cout<<"\nSixteen 48bits keys are\n";
    for (size_t i = 0; i < 16;  i++) {
        for (size_t j = 0; j < 48; j++)  cout<<keys[i][j];
        cout<<endl;
    }
    encode (bmsg, ip, keys, c, flag);                                                                  //function call
}

int main(int argc, char **argv) 
{

    char cipher[12], msg[12], msg_ascii[8]; 
    int arr1[12] = {0};

    memset (cipher, '\0', 12);
    memset (msg, '\0', 12);  
    memset (msg_ascii, '\0', 8); 

    if (argc != 4) 
    {
        cout<<"Incorrect input arguments\nUsage ./des <-e/-d> <message> <key>\n";
        exit(-1);
    }
  
    else 
    {
        if (strcmp(argv[1], "-e") == 0) {
            cout<<"\nEncryption\n";
            des (argv[2], strlen (argv[2]), argv[3], strlen(argv[3]), cipher, 0);                             //Passing message and key as arguments      
            cout<<"Cipher in base64\n";
            for (size_t i = 0; i < strlen(cipher); i++) {
               cout<<cipher[i]; }
        }

	else  {
            cout<<"Decryption\n"; 
	    des(argv[2], strlen(argv[2]), argv[3], strlen(argv[3]), msg, 1);
            //des (cipher, strlen (cipher), argv[3], strlen (argv[3]), msg, 1);

            size_t i = 0;
            int cur, prev, digitsum;

            while ( i < strlen (msg)) {
                cur =  B64 (msg [i]);

                if (cur != -1) {
                digitsum = i % 4;

                switch (digitsum)
                {
                    case 0:
                        //do nothing
                        break;
                    case 1:
                        arr1[i] = (prev << 2) | (cur >> 4);
                        break;
                   case 2:
                        arr1[i] = ((prev & 0x0f) << 4) | (cur >> 2);
                        break;
                   case 3:
                       arr1[i] = ((prev & 3) << 6) | (cur);
                       break;

                }
            }
            prev = cur;
            ++i;
          }

              int index = 0;

              for (size_t i = 0; i < 12; i++) {
                  if (arr1[i] != 0) {
                      msg_ascii[index++] = (char) arr1[i];
                  }
              }
            cout<<"\nDecrypted Message\n";    
            for (size_t i = 0; i < strlen(msg_ascii); i++) {
                cout<<msg_ascii[i];
            }
	}
    }

    cout<<endl;
    return 0; 
}
