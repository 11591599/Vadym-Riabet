#pragma once

bool VerifySignature(const unsigned char* PublicKey,
        const unsigned char* msg,           /* IN: [msg_size bytes] message to sign */
        unsigned int msg_size,              /* IN: size of message */
        const unsigned char* signature);    /* IN: [64 bytes] signature (R,S) */