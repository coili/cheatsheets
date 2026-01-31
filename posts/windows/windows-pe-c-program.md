## Windows PE C Program
Category: Windows

### Introduction

Build : 
1. Code C / C++ -> compilé
2. x86 Assembly -> Code machine
3. Exécuté sur hardware

**User Land** : une application démarre un processus en user-land, avec son propre espace d'adressage virtuel privé et sa propre table des descripteurs (handle table).
**Kernel Land** : les applications partagent leur espace d'adressage virtuel.

### PE Header

Le PE Header fournit des informations à l'OS sur comment mapper le fichier en mémoire. Le code possède des régions désignées nécessitant une protection mémoire différente (RWX).

![[..\images\pe-header.png]]

### Disposition de la mémoire

**Stack** (pile) : ajout et suppression de la mémoire avec LIFO ;
**Tas** (heap) : région pour l'allocation dynamique de la mémoire ;
**Image du programme** (program image) : le code exécutable du PE dans la mémoire ; 
**DLL** : les images des DLLs référencées par le PE ;
**TEB** (Thread Environment Block) : informations à propos du/des thread(s) en cours d'exécution ;
**PEB** (Process Environment Block) : informations à propos des modules et processus chargés.

![[..\images\win-32-memory-map.png]]

### La pile (Stack)

Les données sont soit poussées vers le haut, soit retirées de la structure de données de la pile.

Le registre **EBP** (Base Pointer) est utilisé pour stocker les références dans la pile.

## Langage assembleur x86

### Introduction

L'architecture x86 est **little indian** :

| Octet       | Little Indian |
| ----------- | ------------- |
| A0 A1 A2 A3 | A3 A2 A1 A0   |
### Instructions et opcodes

Chaque instruction représent un opcode (code hexa), indiquant à la machine quoi faire après.

Trois catégories d'instructions : 
1. Déplacement et accès aux données (data movement / access) ;
2. Arithmétique / logique ; 
3. Contrôle de flux (control flow).

Instructions basiques : 
- **mov** / **lea** : data movement, access ;
- **add** / **sub** : arithmétique ;
- **or** / **and** / **xor** : logique ;
- **shr** / **shl** : logique ;
- **ror** / **rol** : logique ;
- **jmp** / **jne** / **jnz** / **jnb** : control flow ;
- **push** / **pop** / **call** / **leave** / **enter** / **ret** : control flow.

Par exemple :

| Instruction            | Opcode            |
| ---------------------- | ----------------- |
| mov ecx, [0xaaaaaaaa]; | 8B 0D AA AA AA AA |
### Registres

| Registre | Description             |
| -------- | ----------------------- |
| EAX      | Registre accumulateur   |
| EBX      | Registre de base        |
| ECX      | Registre compteur       |
| EDX      | Registre de données     |
| ESI      | Index de la source      |
| EDI      | Index de la destination |
| EBP      | Base Pointer            |
| ESP      | Stack Pointer           |

Le registre **EIP** (Instruction Pointer) contient l'adresse de la prochaine instruction a exécuter.

