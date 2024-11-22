#pragma once
#define SEEDBYTES 32
#define CRHBYTES 48
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#define POLYT1_PACKEDBYTES 320
#define POLYT0_PACKEDBYTES 416

#define K_87 8
#define L_87 7
#define K_65 6
#define L_65 5
#define K_44 4
#define L_44 4

#define CTILDEBYTES_87 64
#define CTILDEBYTES_65 48
#define CTILDEBYTES_44 32

#define ETA_44 2
#define TAU_44 39
#define BETA_44 78
#define GAMMA1_44 (1 << 17)
#define GAMMA2_44 ((Q - 1) / 88)
#define OMEGA_44 80

#define POLYZ_PACKEDBYTES_44 576
#define POLYW1_PACKEDBYTES_44 192
#define POLYETA_PACKEDBYTES_44 96

#define ETA_65 4
#define TAU_65 49
#define BETA_65 196
#define GAMMA1_65 (1 << 19)
#define GAMMA2_65 ((Q - 1) / 32)
#define OMEGA_65 55

#define POLYW1_PACKEDBYTES_65 128
#define POLYETA_PACKEDBYTES_65 128

#define ETA_87 2
#define TAU_87 60
#define BETA_87 120
#define GAMMA1_87 (1 << 19)
#define GAMMA2_87 ((Q - 1) / 32)
#define OMEGA_87 75

#define POLYZ_PACKEDBYTES_65 640
#define POLYZ_PACKEDBYTES_87 640
#define POLYZ_PACKEDBYTES_44 576

#define POLYW1_PACKEDBYTES_87 128
#define POLYW1_PACKEDBYTES_44 192

#define POLYETA_PACKEDBYTES_87 96
#define POLYETA_PACKEDBYTES_44 96
