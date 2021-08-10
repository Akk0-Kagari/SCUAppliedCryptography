#include <stdio.h>
#include <string.h>
#include<openssl/sha.h>

#include "mzc_base64.h"
#include "mzc_rsa.h"
#include "aes.h"

#define MAX_DATA_LEN 1024
#define SHA256_LENTH 32

typedef struct {
    char* keyfile;//乙的私钥
    char* vifile;//aes的初始向量
    char* keycipher;//甲发给乙的加密后密钥
    char* cipherfile;//密文
    char* sign;//甲的签名
    char* mode;
    char* recvkey;
    char* recvplain;
    char* pbk_a;//甲的公钥
    char* plainfile;
}s_param;

int keycipherDecryption(char* keycipherName, char* keyfileName, char* recvkeyfileName);//获取文件加解密密钥
int signatureVertify(char* pubkeyName, char* signfileName, char* recvplainName);//验证证书
char* readfile(char* path, int* length);
int d2h(int a, char* res);//dec2hex
int datacheck(char* plainfile,char* recvplainfile);
int shatest(char* strFilePath);//sha的测试函数并生成了甲的签名
int test();

int main(int argc, char* argv[])
{
    s_param param;
    int i = 1;
    param.cipherfile = "a_cipher.txt";
    param.keycipher = "a_cipher_key.txt";
    param.keyfile = "childpvk_b.pem";//乙的私钥证书
    param.mode = "A";
    param.sign = "a_sign.txt";
    param.vifile = "a_vi.txt";
    param.recvkey = "a_recvkey.txt";
    param.recvplain = "a_recvplain.txt";
    param.pbk_a = "childpbk_a.pem";
    param.plainfile="a_plain.txt";
    while (i < argc)
    {
        if (!strcmp(argv[i], "-c"))
            param.cipherfile = argv[i + 1];//密文文件
        else if (!strcmp(argv[i], "-kc"))
            param.keycipher = argv[i + 1];//加密的密钥
        else if (!strcmp(argv[i], "-k"))
            param.keyfile = argv[i + 1];//乙的私钥
        else if (!strcmp(argv[i], "-m"))
            param.mode = argv[i + 1];//模式
        else if (!strcmp(argv[i], "-s"))
            param.sign = argv[i + 1];//甲的数字签名
        else if (!strcmp(argv[i], "-p"))
            param.plainfile = argv[i + 1];//甲的明文
        else if (!strcmp(argv[i], "-ka"))
            param.pbk_a = argv[i + 1];//甲的公钥
        else if (!strcmp(argv[i], "-rp"))
            param.recvplain = argv[i + 1];//恢复的明文
        else if (!strcmp(argv[i], "-rk"))
            param.recvkey = argv[i + 1];//恢复的密钥
        i += 2;
    }
    if (!strcmp(param.mode, "A")) {
        keycipherDecryption(param.keycipher, param.keyfile, param.recvkey);
        printf("文件解密密钥已获取！\n");
    }
    else if (!strcmp(param.mode, "B")) {
        deCBC(param.cipherfile, param.recvkey, param.recvplain, param.vifile);
        printf("文件解密已完成！\n");
    }
    else if (!strcmp(param.mode, "C")) {
        signatureVertify(param.pbk_a, param.sign, param.recvplain);
        printf("签名验证已完成！\n");
    }
    else if (!strcmp(param.mode, "D")) {
        datacheck(param.plainfile, param.recvplain);
        printf("数据校验已完成！\n");
    }
    else
        printf("Mode error!");
    printf("DONE!");
    getchar();
    return 0;
}

/*  读取文件中的所有内容
*   参数：path:文件路径    len：获取长度（执行后得到）
*/
char* readfile(char* path, int* length)
{
    FILE* pfile;
    char* data;

    pfile = fopen(path, "rb");
    if (pfile == NULL)
    {
        return NULL;
    }
    fseek(pfile, 0, SEEK_END);
    *length = ftell(pfile);
    data = (char*)malloc((*length + 1) * sizeof(char));
    rewind(pfile);
    *length = fread(data, 1, *length, pfile);
    data[*length] = '\0';
    fclose(pfile);
    return data;
}

/*  获取文件加解密密钥
*   参数：keycipher：乙公钥加密后的密钥  keyfile：乙的密钥证书
* 
*/
int keycipherDecryption(char* keycipherName, char* keyfileName, char* recvkeyfileName) {
    FILE* recvkeyfile = fopen(recvkeyfileName,"w");
    unsigned char privateKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    int pvkkey_len = 0;
    int encrypted_length = 0;

    char* temp = NULL;
    

    // 需要初始化，否则解密出来的字符串会有多余的乱码
    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(privateKey, '\0', sizeof(privateKey));
    
    temp = readfile(keyfileName, &pvkkey_len);
    memcpy(privateKey, temp, pvkkey_len);
    
    temp = readfile(keycipherName, &encrypted_length);
    memcpy(encrypted_str, temp, encrypted_length);

    int decrypted_length = private_key_decrypt(encrypted_str, encrypted_length, privateKey, decrypted_str);
    //printf("%d\n", encrypted_length);
    if (decrypted_length == -1)
    {
        printf("Public Decrypt failed\n");
    }
    printf("Decrypted Text = %s\n", decrypted_str);
    printf("Decrypted Length = %d\n", decrypted_length);
    fwrite(decrypted_str, sizeof(char), decrypted_length, recvkeyfile);
    return 0;
}

/*  10进制转16进制
*   参数：a：十进制数   res：结果的字符串
*/
int d2h(int a, char* res) {
    char hex[2] = "";
    int ch1 = 0, ch2 = 0;
    ch1 = a / 16;
    switch (ch1)
    {
    case 15:
        hex[0] = 'f';
        break;
    case 14:
        hex[0] = 'e';
        break;
    case 13:
        hex[0] = 'd';
        break;
    case 12:
        hex[0] = 'c';
        break;
    case 11:
        hex[0] = 'b';
        break;
    case 10:
        hex[0] = 'a';
        break;

    default:
        hex[0] = ch1 + 48;
        break;
    }
    ch2 = a % 16;
    switch (ch2)
    {
    case 15:
        hex[1] = 'f';
        break;
    case 14:
        hex[1] = 'e';
        break;
    case 13:
        hex[1] = 'd';
        break;
    case 12:
        hex[1] = 'c';
        break;
    case 11:
        hex[1] = 'b';
        break;
    case 10:
        hex[1] = 'a';
        break;

    default:
        hex[1] = ch2 + 48;
        break;
    }
    strncpy(res, hex, 2);
    return 0;
}

/*  签名验证
*   参数：pubkeyName：公钥证书文件名   signfileName：签名文件名  recvplainName：恢复的文件名
*/
int signatureVertify(char* pubkeyName, char* signfileName, char* recvplainName) {
    SHA256_CTX sha256_ctx;
    FILE* fp = NULL;
    unsigned char SHA256result[SHA256_LENTH];
    char DataBuff[MAX_DATA_LEN];
    int len;
    int t = 0;
    int i;
    int hash_len;
    char tempchunk[3] = { '\0' };
    char shadata[1024] = { '\0' };
    unsigned char publicKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    int pbkkey_len = 0;
    int encrypted_length = 0;
    char* temp = NULL;

    fp = fopen(recvplainName, "rb");  //打开文件

    // 需要初始化，否则解密出来的字符串会有多余的乱码
    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(publicKey, '\0', sizeof(publicKey));

    temp = readfile(pubkeyName, &pbkkey_len);
    memcpy(publicKey, temp, pbkkey_len);

    temp = readfile(signfileName, &encrypted_length);
    memcpy(encrypted_str, temp, encrypted_length);

    int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);
    //printf("%d\n", encrypted_length);
    if (decrypted_length == -1)
    {
        printf("Public Decrypt failed\n");
    }
    printf("Decrypted Signature\n%s\n", decrypted_str);
    

    SHA256_Init(&sha256_ctx);

    while (!feof(fp))
    {
        memset(DataBuff, 0x00, sizeof(DataBuff));

        len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
        if (len)
        {
            t += len;
            //printf("len = [%d] 1\n", len);
            SHA256_Update(&sha256_ctx, DataBuff, len);   //将当前文件块加入并更新SHA256
        }
    }

    //    //printf("len = [%d]\n", t);

    SHA256_Final(SHA256result, &sha256_ctx); //获取SHA256k

    puts("SHA256:");
    for (i = 0; i < SHA256_LENTH; i++) //将SHA256以16进制输出
    {
        printf("%02x", (int)SHA256result[i]);
        d2h((int)SHA256result[i], tempchunk);
        //printf("%s\n", temp);
        strcat(shadata, tempchunk);
    }
    
    printf("\n签名验证：%s\n", strcmp(shadata, decrypted_str)==0 ? "TRUE":"FALSE");

    return 0;
}

/*  数据校验
*   参数：plainfile：明文文件名  recvplainfile：恢复的明文文件名
*/
int datacheck(char* plainfile, char* recvplainfile){
    FILE* f1 = fopen(plainfile, "r");
    FILE* f2 = fopen(recvplainfile, "r");
    char c1 = fgetc(f1);
    char c2 = fgetc(f2);
    while (!feof(f1) && !feof(f2)) {
        if (c1 != c2) 
        { 
            printf("文件内容不一致");  
            return 0; 
        }
        c1 = fgetc(f1);
        c2 = fgetc(f2);
    }
    if (c1 == EOF && c2 == EOF) /* 判断两个文件是否都到结尾 */
        printf("文件内容一致");
    else
        printf("文件内容不一致");
    printf("\n");
    fclose(f1);
    fclose(f2);
    return 0;
}

/*  代码编写过程中的一些测试
*   该部分完成了对甲方密钥的加密
*/
int test() {
    unsigned char plainText[] = "57696C6C69616D53";
    FILE* pvkfile;
    FILE* pbkfile;
    FILE* keycipehrFile;
    unsigned char publicKey[2048];
    unsigned char privateKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    int pvkkey_len = 0;
    int pbkkey_len = 0;
    char* temp = NULL;


    // 需要初始化，否则解密出来的字符串会有多余的乱码
    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(publicKey, '\0', sizeof(publicKey));
    memset(privateKey, '\0', sizeof(privateKey));

    keycipehrFile = fopen("a_cipher_key.txt", "w");
    temp = readfile("childpvk_b.pem", &pvkkey_len);
    memcpy(privateKey, temp, pvkkey_len);
    temp = readfile("childpbk_b.pem", &pbkkey_len);
    memcpy(publicKey, temp, pbkkey_len);

    size_t len = strlen((const char*)plainText);
    printf("Encrypted length =%d\n", len);


    // 公钥加密
    int encrypted_length = public_key_encrypt(plainText, len, publicKey, encrypted_str);
    if (encrypted_length == -1)
    {
        printf("Private Encrypt failed\n");
        exit(0);
    }
    printf("Encrypted Text=%s\n", encrypted_str);
    fwrite(encrypted_str, sizeof(char), encrypted_length, keycipehrFile);
    // 私钥解密
    int decrypted_length = private_key_decrypt(encrypted_str, encrypted_length, privateKey, decrypted_str);
    if (decrypted_length == -1)
    {
        printf("Public Decrypt failed\n");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypted_str);
    printf("Decrypted Length =%d\n", decrypted_length);

    return 0;
}


/*
* sha测试并生成了甲的签名
*/
int shatest(char* strFilePath) {
    SHA256_CTX sha256_ctx;
    FILE* fp = NULL;
    FILE* signFile = fopen("a_sign.txt", "w");
    unsigned char SHA256result[SHA256_LENTH];
    char DataBuff[MAX_DATA_LEN];
    int len;
    int t = 0;
    int i;
    int hash_len;
    char temp[3] = { '\0' };
    int pvkkey_len;//a的私钥长度
    int pbkkey_len;//a的公钥长度
    char shadata[1024] = { '\0' };
    FILE* pvkfile;
    unsigned char privateKey[2048];
    unsigned char publicKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    char* temppvk = NULL;
    char* temppbk = NULL;
    int enc_len = 0;


    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(publicKey, '\0', sizeof(publicKey));
    memset(privateKey, '\0', sizeof(privateKey));

    fp = fopen(strFilePath, "rb");  //打开文件

    do
    {
        SHA256_Init(&sha256_ctx);

        while (!feof(fp))
        {
            memset(DataBuff, 0x00, sizeof(DataBuff));

            len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
            if (len)
            {
                t += len;
                //printf("len = [%d] 1\n", len);
                SHA256_Update(&sha256_ctx, DataBuff, len);   //将当前文件块加入并更新SHA256
            }
        }

        //    //printf("len = [%d]\n", t);

        SHA256_Final(SHA256result, &sha256_ctx); //获取SHA256

        puts("SHA256:");
        for (i = 0; i < SHA256_LENTH; i++) //将SHA256以16进制输出
        {
            printf("%02x", (int)SHA256result[i]);
            d2h((int)SHA256result[i], temp);
            //printf("%s\n", temp);
            strcat(shadata, temp);
        }
        puts("\n");

    } while (0);
    printf("%s\n", shadata);
    printf("%d\n", strlen(shadata));
    hash_len = strlen(shadata);

    temppvk = readfile("childpvk_a.pem", &pvkkey_len);
    memcpy(privateKey, temppvk, pvkkey_len);
    temppbk = readfile("childpbk_a.pem", &pbkkey_len);
    memcpy(publicKey, temppbk, pbkkey_len);


    int encrypted_length = private_key_encrypt(shadata, hash_len, privateKey, encrypted_str);

    printf("enc:%s\n", encrypted_str);

    fwrite(encrypted_str, sizeof(char), encrypted_length, signFile);

    int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);

    printf("dec:%s\n", decrypted_str);


    fclose(signFile);
    //memset(encrypted_str, '\0', sizeof(encrypted_str));

    //tempencstr = getfileall("D:\\ctf\\crypto\\IntegratedPractice\\IntegratedPractice\\Debug\\NeededFiles\\a_sign.txt", &enc_len);

    //memcpy(encrypted_str, tempencstr, enc_len);

    //printf("%s\t%d\n", encrypted_str,enc_len);

    //int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);

    //printf("%d\n", decrypted_length);

    //printf("decrypt: %s\n", decrypted_str);

    //fclose(fp);
    //fclose(signRead);
    return 0;
}