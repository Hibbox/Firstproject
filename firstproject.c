#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio_ext.h>
#include <sys/stat.h>
#include "sodium.h"
#include <iconv.h>
#include <errno.h>
#define MESSAGE msg
#define MESSAGE_LEN strlen(msg)
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

char * chaine_vers_int(char* code){
    int len=strlen(code);
    char* ret=calloc(2*len, sizeof(char));
    for (int i=0; i<len; i++){
        char* tmp =malloc(sizeof(char)*2);
        sprintf(tmp, "%d", code[i]);
        strcat(ret, tmp);
        strcat(ret, ".");
    }
    return ret;
}

char* int_vers_chaine(const char* code){
    char* copy_code=malloc(sizeof(char)*strlen(code));
    strcpy(copy_code, code);
    //printf("%s", code);
    char* delim=".";
	char *ptr = strtok(copy_code, delim);
    char* ret=calloc(strlen(copy_code), sizeof(char));
    while(ptr!=NULL){
        //printf("%s", ptr);
        
        int tmp_int=atoi(ptr);
        char * tmp=malloc(sizeof(char));
        sprintf(tmp, "%c", tmp_int);
        strcat(ret, tmp);
        ptr = strtok(NULL, ".");
    }
    return ret;
}

void bin_to_hexa2(unsigned char bin[], char hex[], int size)
{
    if (size % 8 != 0)
    {
        printf("Taille binaire non valide. La taille doit être un multiple de 8.\n");
        return;
    } 
    int i;
    for (i = 0; i < size; i++)
    {
        sprintf(&hex[i * 2], "%02X", bin[i]);
        //hex[size * 2] = '\0';
    }
}
// octet par octet
void hex_to_bin2(char data_hex[], unsigned char data_binary[], int size_data_binary)
{
    char octet_hexa_temporaire[3];
    int i = 0;
    while (i < size_data_binary)
    {
        memcpy(octet_hexa_temporaire, &data_hex[i * 2], 2);
        octet_hexa_temporaire[2] = '\0';
        data_binary[i] = (unsigned char)strtol(octet_hexa_temporaire, NULL, 16);
        i++;
    }
}

// faire une fonction qui lis l'entrer utilisateur avec gestion d'erreur fonction(chaine[], longeur)
int lire(unsigned char chaine[], int longueur)
{
    char *pos_entre = NULL; // utilisemessage_clair pour stocker l'add mem du caractere trouver
    int caractere_tmp = 0;  // utilisée pour stocker les caractères lus par la fonction getchar() lorsque cette fonction est utilisée pour vider le buffer d'entrée.

    if (fgets(chaine, longueur, stdin) != NULL) // fgets() lit jusqu'à n-1 caractères ou jusqu'à un saut de ligne ou EOF, ce qui permet d'éviter les dépassements de mémoire.
    {
        pos_entre = strchr(chaine, '\n');
        if (pos_entre != NULL)
        {
            *pos_entre = '\0';
        }
        // Si la variable positionEntree n'est pas NULL, cela signifie qu'un saut de ligne a été trouvé dans la chaîne d'entrée lue par la fonction fgets(). Du coup on le \n est remplacer par un caractere NULL et cela mettra fin a la chainne de caractere
        else
        {
            // Le but est de vider le buffer d'entrée en lisant tous les caractères restants jusqu'à un saut de ligne ou EOF.
            __fpurge(stdin);
            /*while( caractere_tmp != '\n' && caractere_tmp != EOF)
                caractere_tmp = getchar(); */
        }
        return 1;
    }
    else
    {
        __fpurge(stdin);
        return 0;
    }
}

void chiffrement_m(unsigned char secret_key[]) // la variable secret_key contient la cle secrete qui contiendra un noimbre aleatoirement generer
{

    unsigned char *msg = malloc(sizeof(char) * 1000);

    puts("Veuillez entrez un message de votre choix \n ps: ne pas depasser 1000 caractere ! \n");
    lire(MESSAGE, 1000);
    
    unsigned char ciphertext[CIPHERTEXT_LEN];
    unsigned char nonce[crypto_secretbox_NONCEBYTES]; // variable nonce permet de specifier l'unicite de chaque message et crypto_secretbox_NONCEBYTES permet de generer un nombre aleatoire

    randombytes_buf(nonce, sizeof(nonce)); // permet de generer un nombre d'octert aleatoire de 0 a 0xfffffff

    // representation du nonce binaire -> hexa
    unsigned char *nonce_hex = chaine_vers_int(nonce);

    // chiffrement du message
    printf( "%s", ciphertext);

    if (crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, secret_key) == 0)
    {
        puts("chiffrement reussi !");
    }
    else
        puts("ERREUR");
    // representation du texte chiffre en string hexadecimal
    unsigned char *cipher_text_hexa = chaine_vers_int(ciphertext);
    // affichons le couple du nonce + texte chiffre
    puts("NONCE : Texte chiffre (a copier)");
    printf("%s:%s\n", nonce_hex, cipher_text_hexa);
}

void chiffrement_f(unsigned char secret_key[])
{
    char chemin_relatif[100];
    unsigned char *buffer = NULL;
    size_t size_file = 0; // taille d'octet du fichier

    puts("Entrez le chemin relatif ou le nom du fichier ?\n");
    lire(chemin_relatif, 100);
    // le fichier existe-t-il ET est-t-il accessible en lecture ?
    FILE *fichier = NULL;
    fichier = fopen(chemin_relatif, "r");
    if (fichier == NULL)
    {
        fprintf(stderr, "erreur d'ouvertur fichier ");
        exit(1);
    }
    // lecture du contenue (octet, pointeur vers un tampon où sera stocké le contenu lu, la taille de chaque élément à lire, le nombre d'éléments à lire et un pointeur vers le fichier à lire )

    fseek(fichier, 0, SEEK_END); // find size, deplace le curseur de l'octet 0 a la fin du fichier
    size_file = ftell(fichier);  // permet de connaître la position actuelle du pointeur de position dans un fichier ouvert
    fseek(fichier, 0, SEEK_SET); // permet de remettre le curseur au debut

    buffer = (unsigned char *)malloc(size_file * sizeof(unsigned char));
    if (buffer == NULL)
    {
        fprintf(stderr, "erreur d'allocation de memoire");
        exit(1);
    }
    // lire le contenue du fichier
    size_t read_bytes = fread(buffer, sizeof(unsigned char), size_file, fichier);
    if (read_bytes != size_file)
    {
        fprintf(stderr, "erreur taille de fichier");
        exit(1);
    }
    // fermer le fichier
    fclose(fichier);

    // allocation de taille necessaire pour chiffrer le message
    unsigned int size_buff = sizeof(buffer);
    unsigned char *file_encrypt = malloc(size_buff + crypto_secretbox_MACBYTES);
    if (file_encrypt == NULL)
    {
        fprintf(stderr, "Erreur d'allocation");
        exit(1);
    }
    // generation du nonce
    char nonce_file[crypto_secretbox_NONCEBYTES]; // variable nonce permet de specifier l'unicite de chaque message et crypto_secretbox_NONCEBYTES permet de generer un nombre aleatoire

    randombytes_buf(nonce_file, sizeof(nonce_file)); // permet de generer un nombre d'octert aleatoire de 0 a 0xfffffff

    // representation du nonce binaire -> hexa
    char nonce_file_hex[crypto_secretbox_NONCEBYTES * 2 + 1];
    bin_to_hexa2(nonce_file, nonce_file_hex, sizeof(nonce_file));

    // chiffrement du fichier
    if (crypto_secretbox_easy(file_encrypt, buffer, size_buff, nonce_file, secret_key) == 0)
    {
        puts("chiffrement reussi !");
    }
    else
        puts("ERREUR");

    // modification du nom du fichier
    char new_file_name[strlen(chemin_relatif) + 10];
    strcpy(new_file_name, chemin_relatif);
    strcat(new_file_name, ".encrypted");
    rename(chemin_relatif, new_file_name);

    // modification des autorisation
    chmod("new_file_name", S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    // representation du fichier chiffrer en string hexa
    char file_encrypt_hexa[sizeof(file_encrypt) * 2 + 1];
    bin_to_hexa2(file_encrypt, file_encrypt_hexa, sizeof(file_encrypt));
    puts("NONCE : file chiffre (a copier)");
    printf("%s:%s\n", nonce_file_hex, file_encrypt_hexa);
    free(file_encrypt);
    free(buffer);
}


void dechiffrement_m(unsigned char secret_key[])
{
    unsigned char *msg = malloc(sizeof(char) * 1000);
// lecture du texte chiffré
	unsigned char *couple_nonce_chiffre; // taille max du couple nonce + chiffre + separateur
	printf("Entrez un couple NONCE : TEXTE CHIFFRE (coller)\n");
	lire(couple_nonce_chiffre, 1000);

// On extrait le nonce et le convertit en binaire
	//hex_to_bin2(couple_nonce_chiffre, nonce_bin, crypto_secretbox_NONCEBYTES); 

// On extrait le texte chiffré et le convertit en binaire
 // indice u premier caractere du chiffré dans le couple nonce chiffré)
	int taille_texte_chiffre = strlen(couple_nonce_chiffre); // On calcule la taille du chiffre (taille du couple moins le nonce et le séparateur ":")

    char *nonceee = strtok(couple_nonce_chiffre, ":");
    char *text_chiffre = strtok(NULL, ":");
    printf("%s\n>>%s<<\n", nonceee, text_chiffre);

	//hex_to_bin2(&couple_nonce_chiffre[indice_debut_chiffre], texte_chiffre_bin, sizeof(texte_chiffre_bin));

// On calcule la taille du texte en clair
	unsigned char *decrypted = malloc(sizeof(char) * MESSAGE_LEN);// le message en clair fait la taille du chiffre binaire moins le code MAC, plus 1 charactere NULL final
	unsigned char *texte_cipher = malloc(sizeof(char) * CIPHERTEXT_LEN); // La taille du chiffré binaire est la moitié de la taille du chiffré hexa
	unsigned char *nonce = malloc(sizeof(char) * crypto_secretbox_NONCEBYTES);

	nonce = int_vers_chaine(nonceee);
    printf( "%s\n", text_chiffre);
    texte_cipher = int_vers_chaine(text_chiffre);
    printf( "%s\n", text_chiffre);
    printf( "%s\n", texte_cipher);


// On déchiffre le texte chiffré avec le nonce et la clé secrète
if (crypto_secretbox_open_easy(decrypted, texte_cipher + crypto_secretbox_NONCEBYTES, CIPHERTEXT_LEN - crypto_secretbox_NONCEBYTES, nonce, secret_key) == 0) 
{
    
	puts("dechiffrement reussi !");
        
	decrypted[MESSAGE_LEN] = '\0'; // On ajoute le charactère NULL final

    // Conversion en UTF-8
    iconv_t cd = iconv_open("UTF-8", "ISO_8859-1");
    if (cd == (iconv_t) -1) {
        perror("iconv_open");
        exit(EXIT_FAILURE);
    }

    size_t decrypted_msg_len = strlen(decrypted);
    char *decrypted_utf8 = malloc(sizeof(decrypted_msg_len) + 1);

    if (decrypted_utf8 == NULL)
    {
        fprintf(stderr, "Erreur d'allocation");
        exit(1);
    }

    char *in_ptr = decrypted;
    size_t in_left = decrypted_msg_len;
    char *out_ptr = decrypted_utf8;
    size_t out_left = decrypted_msg_len * 4;

    if (iconv(cd, &in_ptr, &in_left, &out_ptr, &out_left) == (size_t) -1)
    {
        perror("iconv");
        exit(EXIT_FAILURE);
    }

    iconv_close(cd);

    puts("Message déchiffré :");
    printf("%s\n", decrypted);
    }
    else {
    puts("Echec de déchiffrement !");
}


}

int main()
{
    // char *key_encrypt = malloc(((strlen(cle_secret) * 4) + 1)* sizeof(unsigned char));
    if (sodium_init() < 0) // HEAP SUMMARY:
    {
        puts("Erreur de la librairie");
        return EXIT_FAILURE;
    }
    unsigned char secret_key[crypto_secretbox_KEYBYTES];
    randombytes_buf(secret_key, crypto_secretbox_KEYBYTES); // generation de nombre pseudo aleatoire
    char choix[2];
    int int_choix;
    printf("->");
    do
    {
        int_choix = -1;
        puts("---Menu Cryptographique---");
        puts(" Faite un choix selon les options pour continuer :");
        puts(" 1 - chiffrer un message");
        puts(" 2 - dechiffrer un message");
        puts(" 3 - chiffrer un fichier");
        puts(" 4 - dechiffrer un fichier");
        puts(" 0 - Exit");

        lire(choix, 2);
        sscanf(choix, "%d", &int_choix);
        switch (int_choix)
        {
        case 1:
            chiffrement_m(secret_key);
            break;
        case 2:
            dechiffrement_m(secret_key);
            break;
        case 3:
            chiffrement_f(secret_key);
            break;
        case 4:
            /* code dechiffrer un fichier */
            break;
        case 0:
            break;
        default:
            printf("ERROR : Unknown commande %s\n", choix);
            break;
        }

    } while (int_choix != 0);

    return EXIT_SUCCESS;
}
