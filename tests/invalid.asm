section .data
msg1 dw 'HELLO, WORLD'
msg2 db 10
section .text;
mov r0,10

;The following line will raise
;a lexical error
banana
;test