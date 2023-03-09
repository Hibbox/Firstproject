# Chiffrement/dechiffrement d'un fichier/message (non terminer)

https://forthebadge.com/images/badges/gluten-free.svg

Description : l'objectif de ce projets etait de comprendre comment un message/fichier est chiffrer avec un algorithme de chiffrement.
Ce projet est coder dans le langage de programmation C. J'ai Implémentez une fonction qui prend en entrée une chaîne de caractères et qui chiffre cette chaîne en utilisant la clé publique.
La sortie de cette fonction est une chaîne de caractères contenant les valeurs chiffrées.
Ensuite j'ai implemeter une fonction qui prend en entrée une chaîne de caractères chiffrée et qui déchiffre cette chaîne en utilisant la clé privée.
e projets ma appris a connaitre des termes tel que l'entropie de maniere securiser ainsi que les 4 maniere de la securiser :
- Generation 
- Collecte
- Stockage
- Utilisation.
J'ai appris aussi la conversion de binaire en hexadecimal.

## Pour commencer
git clone git@github.com:Hibbox/Firstproject.git
### Pré-requis
Vous devez obligatoirement installer la librairie libsodium -> https://download.libsodium.org/libsodium/releases/.
./configure
make && make check
sudo make install
### Installation
gcc firstcrypt.c -o [nom_de_sorie] -lsodium   
## Démarrage
./[nom_de_sortie]

## Fabriqué avec
je me suis aider de l'aide de la doc libsodium

## Contributing

Si vous souhaitez contribuer, m'aider a trouver des solutiona mes problemes je suis preneur -> hibooxx9@gmail.com

## Versions
**Dernière version stable :** 1.0

## Probleme rencontrer
le projets est en standby pour la raison suivante :
- j'arrive chiffre mon message avec le nonce + MACBYTE mais pour arriver a le dechiffrer impossible il ne me met pas mon message final, je pense qu'il doit avoir un probleme lors de conversion du couple nonce:msg_chiffre.

