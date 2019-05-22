### GUIDE TO USE 


#### Step 1: Install Java
- Download and install: [Java SE Development Kit 8](https://www.oracle.com/technetwork/java/javaee/downloads/jdk8-downloads-2133151.html)
- Or via Terminal: 

```bash
$ brew cask install java 
$ java -version
``` 

- Check Java version:

```
java version "1.8.0_211"
Java(TM) SE Runtime Environment (build 1.8.0_211-b12)
Java HotSpot(TM) 64-Bit Server VM (build 25.211-b12, mixed mode)
```

#### Step 2: Install MAVEN
Open Terminal:
             
```bash
$ brew install maven 
```  

#### Step 3: Download and install [IntelliJ IDEA](https://www.jetbrains.com/idea/download/#section=mac)

#### Step 4: Download and open project ysoserial via IntelliJ

![open project](https://github.com/hominhtuong/use-ysoserial/blob/master/resources/open-project.png)

#### Step 5: Change config:

- change value of `DEFAULT_SLEEP_TIME` and `URL_TO_READ` in class `Attack.java`
ex:
```java
public class Attack {
    
    public static final long DEFAULT_SLEEP_TIME = 30000; // 30s
    public static final String URL_TO_READ = "your-URL";
}
```

#### Step 6: Run Test

- Open class `AttackTest`

- run `testPayload4` to generate `sleep payloads`

![run project](https://github.com/hominhtuong/use-ysoserial/blob/master/resources/run-test.png)

- run `testPayload3` to read local file ( `/etc/passwd` )

