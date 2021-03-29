section .data
msg1 dw 10,20,30
msg2 db 1,2,3
msg3 db 'HELLO, WORLD!\n'
section .text
mov r0,10
mov r1,20
add r0,r1
mov r0,msg1
mov r1,r0
mov r0,msg1[1]
add r1,r0