package com.finalproject.bttd.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;
import org.springframework.util.StopWatch;

@Aspect
@Component
@Slf4j
public class PerformanceAspect {
    @Pointcut("@annotation(com.finalproject.bttd.annotation.RunningTime)")
    private void enableRunningTime(){}


    //기본 패키지의 모든 메서드
    @Pointcut("execution(* com.finalproject.bttd..*.*(..))")
    private void cut(){};


    //실행시점 설정 : 두저곤을 모두 만족 하는 대상을 전후로 부가기능을 삽입
    @Around("cut() && enableRunningTime()")
    public void loggingRunningTime(ProceedingJoinPoint joinPoint) throws Throwable {
        //메소드 수행전, 측정시작
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        //메소드를 수행
        Object returningObj = joinPoint.proceed();

        //메소드 수행후 , 측정 종료 및 로깅
        stopWatch.stop();

        //메소드명
        String methodName = joinPoint.getSignature().getName();
        log.info("{}=>",methodName, stopWatch.getTotalTimeSeconds());



    }

}
