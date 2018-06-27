;/*****************************************************************************
; * @file:    startup.s
; * @purpose: CMSIS Cortex-M3 Core Device Startup File 
; *           for the ARM 'Microcontroller Prototyping System' 
; * @version: V1.0
; * @date:    
; *
; *****************************************************************************/

;* <<< Use Configuration Wizard in Context Menu >>>  

; Amount of memory (in bytes) allocated for Stack
; Tailor this value to your application needs
; <h> Stack Configuration
;   <o> Stack Size (in Bytes) <0x0-0xFFFFFFFF:8>
; </h> 

; Stack Configuration
Stack_Size      EQU     0x00000800
                AREA    STACK, NOINIT, READWRITE, ALIGN=3
Stack_Mem       SPACE   Stack_Size
__initial_sp


; <h> Heap Configuration
;   <o>  Heap Size (in Bytes) <0x0-0xFFFFFFFF:8>
; </h>

; Heap Configuration
Heap_Size       EQU     0x00000f00
                AREA    HEAP, NOINIT, READWRITE, ALIGN=3
__heap_base
Heap_Mem        SPACE   Heap_Size
__heap_limit

                PRESERVE8
                THUMB

; Vector Table Mapped to Address 0 at Reset

                AREA    RESET, DATA, READONLY
                EXPORT __Vectors

__Vectors       
				DCD     __initial_sp                ; Top of Stack
                DCD     Reset_Handler               ; Reset Handler
                DCD     NMI_Handler                 ; NMI Handler 不可屏蔽中断
                DCD     HardFault_Handler           ; Hard Fault Handler
                DCD     MemManage_Handler           ; MPU Fault Handler
                DCD     BusFault_Handler            ; Bus Fault Handler
                DCD     UsageFault_Handler          ; Usage Fault Handler
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     0                           ; Reserved
                DCD     SVC_Handler                 ; SVCall Handler ，相当于SWI
                DCD     DebugMon_Handler            ; Debug Monitor Handler
                DCD     0                           ; Reserved
                DCD     PendSV_Handler              ; PendSV Handler
                DCD     SysTick_Handler             ; SysTick Handler，系统滴答定时器，即周期性溢出的时基定时器

                ; External Interrupts
                DCD     WDT_IRQHandler				; 0:  WDT_IRQHandler  
                DCD     TIMER_IRQHandler			; 1:  TIMER_IRQHandler 
                DCD     0                       	; 2:  Reserved 
                DCD     UARTA_IRQHandler		  	; 3:  UARTA_IRQHandler 
                DCD     SPIA_IRQHandler	          	; 4:  SPIA_IRQHandler
                DCD     SPIB_IRQHandler			    ; 5:  SPIB_IRQHandler
                DCD     GPIOA_IRQHandler			; 6:  GPIOA_IRQHandler 
                DCD     USB_IRQHandler             	; 7:  USB_IRQHandler 
                DCD     0					        ; 8:  Reserved 
                DCD     SM1_IRQHandler				; 9:  SM1_IRQHandler/SCB2_IRQHandler 
                DCD     DES_IRQHandler				; 10: DES_IRQHandler 
                DCD     ECC_IRQHandler              ; 11: ECC_IRQHandler
                DCD     EFC_IRQHandler              ; 12: EFC_IRQHandler
                DCD     0							; 13: Reserved
                DCD     I2C_IRQHandler              ; 14: I2C_IRQHandler
                DCD     MS7816RST_IRQHandler        ; 15: MS7816RST_IRQHandler
                DCD     SM4_IRQHandler				; 16: SM4_IRQHandler
                DCD     GPIOB_IRQHandler			; 17: GPIOB_IRQHandler
                DCD     DMA_IRQHandler          	; 18: DMA_IRQHandler
                DCD     CCPWM_IRQHandler            ; 19: CCPWMA_IRQHandler
                DCD     SDIO_IRQHandler             ; 20: SDIO_IRQHandler
                DCD     UARTB_IRQHandler            ; 21: UARTB_IRQHandler
                DCD     BCH_IRQHandler              ; 22: BCH_IRQHandler
                DCD     NFM_IRQHandler              ; 23: NFM_IRQHandler
                DCD     EMW_IRQHandle               ; 24: EMW_IRQHandle
                DCD     0			              	; 25: Reserved
                DCD     SENSOR_IRQHandler           ; 26: SENSOR_IRQHandler
                DCD     ISO7816MS_IRQHandler        ; 27: ISO7816MS_IRQHandler
                DCD     0              			    ; 28: Reserved 
                DCD     0			    		    ; 29: Reserved
                DCD     0                           ; 30: Reserved
                DCD     WAKEUP_IRQHandler           ; 31: WAKEUP_IRQHandler

                AREA    |.text|, CODE, READONLY

; Reset handler routine
Reset_Handler   PROC
                EXPORT  Reset_Handler             [WEAK]
                IMPORT  __main

                ;IMPORT  __set_CONTROL
				;MOVS     R0, #0x01		           ;用户级，Thread和handler模式共享同一个堆栈MSP
				;BL 	    __set_CONTROL	       ;转入用户级线程模式				
                LDR     R0, =__main
                BX      R0	                       ;BX:跳转到由寄存器给出的地址,	B:跳转到标号处对应的地址
                ENDP

; Dummy Exception Handlers (infinite loops which can be modified)
NMI_Handler     PROC
                EXPORT  NMI_Handler               [WEAK]
                B       .
                ENDP
HardFault_Handler\
                PROC
                EXPORT  HardFault_Handler         [WEAK]
                B       .
                ENDP
MemManage_Handler\
                PROC
                EXPORT  MemManage_Handler         [WEAK]
                B       .
                ENDP
BusFault_Handler\
                PROC
                EXPORT  BusFault_Handler          [WEAK]
                B       .
                ENDP
UsageFault_Handler\
                PROC
                EXPORT  UsageFault_Handler        [WEAK]
                B       .
                ENDP
SVC_Handler     PROC                
                EXPORT  SVC_Handler               [WEAK]
                B       .
                ENDP
DebugMon_Handler\
                PROC
                EXPORT  DebugMon_Handler          [WEAK]
                B       .
                ENDP
PendSV_Handler  PROC
                EXPORT  PendSV_Handler            [WEAK]
                B       .
                ENDP
SysTick_Handler PROC
                EXPORT  SysTick_Handler           [WEAK]
                B       .
                ENDP
				
Default_Handler PROC
                EXPORT   WDT_IRQHandler           [WEAK] 
                EXPORT   TIMER_IRQHandler         [WEAK]
                EXPORT   UARTA_IRQHandler         [WEAK]
                EXPORT   SPIA_IRQHandler          [WEAK]
                EXPORT   SPIB_IRQHandler          [WEAK]
                EXPORT   GPIOA_IRQHandler         [WEAK]
                EXPORT   USB_IRQHandler           [WEAK]
                EXPORT   SM1_IRQHandler           [WEAK]
                EXPORT   DES_IRQHandler           [WEAK]
                EXPORT   ECC_IRQHandler           [WEAK]
                EXPORT   EFC_IRQHandler           [WEAK]
                EXPORT   I2C_IRQHandler           [WEAK]
                EXPORT   MS7816RST_IRQHandler     [WEAK]
                EXPORT   SM4_IRQHandler           [WEAK]
                EXPORT   GPIOB_IRQHandler         [WEAK]
				EXPORT	 DMA_IRQHandler			  [WEAK]
                EXPORT   CCPWM_IRQHandler         [WEAK]
                EXPORT   SDIO_IRQHandler          [WEAK]
                EXPORT   UARTB_IRQHandler         [WEAK]
                EXPORT   BCH_IRQHandler           [WEAK]
                EXPORT   NFM_IRQHandler           [WEAK]
                EXPORT   EMW_IRQHandle            [WEAK]
                EXPORT   SENSOR_IRQHandler        [WEAK]
                EXPORT   ISO7816MS_IRQHandler     [WEAK]
				EXPORT   WAKEUP_IRQHandler		  [WEAK]
WDT_IRQHandler          
TIMER_IRQHandler           
UARTA_IRQHandler        
SPIA_IRQHandler         
SPIB_IRQHandler         
GPIOA_IRQHandler        
USB_IRQHandler              
SM1_IRQHandler         
DES_IRQHandler          
ECC_IRQHandler          
EFC_IRQHandler               
I2C_IRQHandler          
MS7816RST_IRQHandler          
SM4_IRQHandler          
GPIOB_IRQHandler 
DMA_IRQHandler
CCPWM_IRQHandler        
SDIO_IRQHandler         
UARTB_IRQHandler        
BCH_IRQHandler          
NFM_IRQHandler          
EMW_IRQHandle                   
SENSOR_IRQHandler       
ISO7816MS_IRQHandler        
WAKEUP_IRQHandler
                B       .
                ENDP
                ALIGN

; User Initial Stack & Heap

                IF      :DEF:__MICROLIB
                
                EXPORT  __initial_sp
                EXPORT  __heap_base
                EXPORT  __heap_limit
                
                ELSE
                
                IMPORT  __use_two_region_memory
                EXPORT  __user_initial_stackheap
__user_initial_stackheap

                LDR     R0, =  Heap_Mem
                LDR     R1, = (Stack_Mem + Stack_Size)
                LDR     R2, = (Heap_Mem +  Heap_Size)
                LDR     R3, = Stack_Mem
                BX      LR

                ALIGN

                ENDIF

                END
