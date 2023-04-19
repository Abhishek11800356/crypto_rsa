//To generate Private key --> openssl genrsa -out private.pem 2048
//To generate Public key  --> openssl rsa -in private.pem -outform PEM -pubout -out public.pem
// To compile file --> gcc -I/usr/include/openssl/ -Wall rsa1.c -o rsa1 -lcrypto -ldl
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
 
int padding = RSA_PKCS1_PADDING;
 
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
 
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}
 
int main(){
 
  char plainText[2048/8] = "Hello Abhi"; //key length : 2048
 
 char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsmERNWo8euCDkq4s927N\n"\
"ZFdfLknhuD0BwHrJJhuqHXX0S0dRHsIDwvv+UD0OHL5lm+ecpD7jEmaD84cHUbFs\n"\
"L04KXxnRmX/FMhrGpFivPT+0KXIOK1FCpTXPfOf5C2n8Q9DjnjYTlAetTmfbLQHr\n"\
"fnyQhOJcXq1WCMfYoD+JrkLGdBmuduZx7BAIRq9RHmV7tZV2fCqc80TgZpiJ7/Fd\n"\
"ncns13LyKq42O7lLaAWAMIX/gIyKlWF8l8jUadKp5J/tgFWnOwHU9KvnQX5xBaUp\n"\
"Bp+g1Ma68KrfxYq8P75PalPmpwsoyRbUzoeRKqg/fuBgp+5ioj9eoX6sc+TjqdrN\n"\
"8wIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

 
 /*"-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
*/
  
 char privateKey[]="-----BEGIN PRIVATE KEY-----\n"\
"MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCyYRE1ajx64IOS\n"\
"riz3bs1kV18uSeG4PQHAeskmG6oddfRLR1EewgPC+/5QPQ4cvmWb55ykPuMSZoPz\n"\
"hwdRsWwvTgpfGdGZf8UyGsakWK89P7Qpcg4rUUKlNc985/kLafxD0OOeNhOUB61O\n"\
"Z9stAet+fJCE4lxerVYIx9igP4muQsZ0Ga525nHsEAhGr1EeZXu1lXZ8KpzzROBm\n"\
"mInv8V2dyezXcvIqrjY7uUtoBYAwhf+AjIqVYXyXyNRp0qnkn+2AVac7AdT0q+dB\n"\
"fnEFpSkGn6DUxrrwqt/Firw/vk9qU+anCyjJFtTOh5EqqD9+4GCn7mKiP16hfqxz\n"\
"5OOp2s3zAgMBAAECgf8GAuIFWiPMXTS8ddwux8u3LrRmCN4xyL2BmOojuyrDYsJz\n"\
"tFe951VK2STtNKwmIJNSSdDrI84RA1ei1ZjY4xRkygR3AV7y/J2QGB+UZa3H1QVV\n"\
"y6pzbUL4mHMlnuePAVS7wIPI8q1EDz1x7nZwgXfJCgV99Sa3GTXZoXDrFTTJ9t+H\n"\
"g6l8Xb54UW3P15OYA5LQJULTkjVXlI5vdSaC2Kl/puj1pyztZMcCjJz+0XKAg2lH\n"\
"3b4H0UxyGud8HcQgdkeElavUnVUlVAb7lt2SXQCgsL1ncX7gOxY0CLIT0cfDpoMl\n"\
"s2iqC4JePqvAXlJGMXiWgT27lr1LANNP+92c1S0CgYEA3KOdHbvMegy5cT6s6Dja\n"\
"EfVlRoDQ2YYKVq+R5yzD878JEYfRwVjLGO9YGQACFbF0MhIzgoEBVphRPR56GZuq\n"\
"Sf/Dbj66eJ2hZx12PyR0lLkN6/pTEtmryN8fu5l9xV2CMBDqJrzvwtD56d8GTuFi\n"\
"/mDC9djDV2zOADKIgp2Wfa0CgYEAzvecikv7xceUwkfY/1774IeEjkxUvD+wuCSb\n"\
"U+zlah79Ar0+dPGlMQzZSwslTpJhKjdRxEXb5S0N948aHCNvZHH6a83cMc1JNxv3\n"\
"VOqnhILd0+wpN0gC4dc0wVdcK+6InUtlbQ85Yvg6mq2Xygp3rvYZwnErH0EcITW9\n"\
"AxLOrh8CgYEAkMIv9TAfqfvrNyd93iZevOWZ+rXNUMomwlUSju/J6IPv+TZ5IjeV\n"\
"mNh/nndo5r60k51pejgVnrD0q/rw9Rgyk7ZgjFZPlY8mNDcaO7c5XdJEFgz4sCds\n"\
"E7CAa177K6B8J/kRBzVywQjGzvBqfRpXDrqBbzc2god6aJq/AaNO90kCgYBZEADT\n"\
"GoOLxqjjOdvNeOhW5LpMKdjE8XtwooAdC3JlylQCW8GGvX3ir67KNk+lkiQx8IBF\n"\
"P/KymkLKZ1BLD4yd4tZqkbnRzI9XIbe7WQchZNdknNnXqitjWCKhmKBXX1x2o71P\n"\
"wx9k0YEWkuEg1oROTCUloWF3H6OlPuTJb8x07QKBgEAlcAZGuc5zOMB+RO2DVasu\n"\
"xB1TTQvEF0stuXrcvHsbc7n7AkXERL/FG0gCvsY4Ae23/Zx/vBSVRcd6Ns6DFRBA\n"\
"zpLFC3XThlhqiI2JzRUkLul6oPHek1hz1o0InqERQyZ9vJHLO3bRnLLtzbD73t/7\n"\
"LjKADWA1MQbXXTxQT7jS\n"\
"-----END PRIVATE KEY-----\n";
 
 
 
 /*"-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";
 */
    
unsigned char  encrypted[4098]={};
unsigned char decrypted[4098]={};
 
int encrypted_length= public_encrypt(plainText,strlen(plainText),publicKey,encrypted);
if(encrypted_length == -1)
{
    printLastError("Public Encrypt failed ");
    exit(0);
}
printf("Encrypted Text =%s\n",encrypted);
printf("Encrypted length =%d\n",encrypted_length);
 
int decrypted_length = private_decrypt(encrypted,encrypted_length,privateKey, decrypted);
if(decrypted_length == -1)
{
    printLastError("Private Decrypt failed ");
    exit(0);
}
printf("Decrypted Text =%s\n",decrypted);
printf("Decrypted Length =%d\n",decrypted_length);
}
