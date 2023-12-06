package com.finalproject.bttd.aop;


import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Slf4j
public class DebuggingAspect {
    @Pointcut("execution(* com.finalproject.bttd.api.*.*(..))") //대상메서드선택
    private void cut(){}

    @Before("cut()")//실행시점 :cut()의 대상이 수행되기 이전에 수행함.
    public void loggingArgs(JoinPoint joinPoint){
        //입력값 가져오기
        Object[] args = joinPoint.getArgs();
        //클래스명
        String className = joinPoint.getTarget().getClass().getSimpleName();
        //메소드명
        String methodName = joinPoint.getSignature().getName();
        //입력값 로깅하기
        for(Object obj : args){ //foreach문
            log.info("{}#{}의 입력값 =>{}", className, methodName, obj);
        }
    }

    @AfterReturning(value ="cut()", returning = "returnObj")
    public void loggingReturnValue(JoinPoint joinPoint, Object returnObj){ //앞에건 cut()의 대상메소드, 뒤에건 리턴값

        String className = joinPoint.getTarget().getClass().getSimpleName();
        //메소드명
        String methodName = joinPoint.getSignature().getName();
        //입력값 로깅하기
        //반환값 로깅
        log.info("{}#{}의 입력값 =>{}", className, methodName, returnObj);

    }

}
