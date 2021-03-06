;PR15293: ARM codegen ice - expected larger existing stack allocation
;RUN: llc -mtriple=arm-linux-gnueabihf < %s | FileCheck %s

;CHECK: foo:
;CHECK: 	sub	sp, sp, #8
;CHECK: 	push	{r11, lr}
;CHECK: 	str	r0, [sp, #12]
;CHECK: 	add	r0, sp, #12
;CHECK: 	bl	fooUseParam
;CHECK: 	pop	{r11, lr}
;CHECK: 	add	sp, sp, #8
;CHECK: 	mov	pc, lr

;CHECK: foo2:
;CHECK: 	sub	sp, sp, #16
;CHECK: 	push	{r11, lr}
;CHECK: 	str	r0, [sp, #12]
;CHECK: 	add	r0, sp, #12
;CHECK: 	str	r2, [sp, #16]
;CHECK: 	bl	fooUseParam
;CHECK: 	add	r0, sp, #16
;CHECK: 	bl	fooUseParam
;CHECK: 	pop	{r11, lr}
;CHECK: 	add	sp, sp, #16
;CHECK: 	mov	pc, lr

;CHECK: doFoo:
;CHECK: 	push	{r11, lr}
;CHECK: 	ldr	r0,
;CHECK: 	ldr	r0, [r0]
;CHECK: 	bl	foo
;CHECK: 	pop	{r11, lr}
;CHECK: 	mov	pc, lr


;CHECK: doFoo2:
;CHECK: 	push	{r11, lr}
;CHECK: 	ldr	r0,
;CHECK: 	mov	r1, #0
;CHECK: 	ldr	r0, [r0]
;CHECK: 	mov	r2, r0
;CHECK: 	bl	foo2
;CHECK: 	pop	{r11, lr}
;CHECK: 	mov	pc, lr


%artz = type { i32 }
@static_val = constant %artz { i32 777 }

declare void @fooUseParam(%artz* )

define void @foo(%artz* byval %s) {
  call void @fooUseParam(%artz* %s)
  ret void
}

define void @foo2(%artz* byval %s, i32 %p, %artz* byval %s2) {
  call void @fooUseParam(%artz* %s)
  call void @fooUseParam(%artz* %s2)
  ret void
}


define void @doFoo() {
  call void @foo(%artz* byval @static_val)
  ret void
}

define void @doFoo2() {
  call void @foo2(%artz* byval @static_val, i32 0, %artz* byval @static_val)
  ret void
}

