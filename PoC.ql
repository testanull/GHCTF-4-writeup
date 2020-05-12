/** @kind path-problem */
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph
import semmle.code.java.dataflow.FlowSources
// import DataFlow::PartialPathGraph


class ConstraintValidatorisValidMethod extends Method{
	ConstraintValidatorisValidMethod(){
		exists(Method base|
		this = base
		and base.hasName("isValid")
		and base.getDeclaringType().getASourceSupertype*().hasName("ConstraintValidator")
		)
	}
}

class ConstraintValidatorContextBuildTemplate extends Method{
	ConstraintValidatorContextBuildTemplate(){
		this.hasName("buildConstraintViolationWithTemplate") and this.getDeclaringType().hasName("ConstraintValidatorContext")
	}
}

class GetSoftOrHardContraints extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(MethodAccess ma, Method m|
			ma.getMethod() = m
			and (m.hasName("getSoftConstraints") or m.hasName("getHardConstraints"))
			and m.getDeclaringType().hasQualifiedName("com.netflix.titus.api.jobmanager.model.job", "Container")
			and ma.getQualifier() = node1.asExpr()
			and ma = node2.asExpr()
		)
	}
}

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

class CollectionStream extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(MethodAccess ma, Method m|
		ma.getMethod() = m
		and m.hasName("stream")
		and m.getDeclaringType().getASourceSupertype().hasQualifiedName("java.util", "Collection")
		and ma.getQualifier() = node1.asExpr()
		and ma = node2.asExpr()
		)
	}
}

class StreamMap extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(MethodAccess ma, Method m|
		ma.getMethod() = m
		and (m.hasName("map") or m.hasName("collect"))
		and m.getNumberOfParameters() = 1
		and m.getDeclaringType().getASourceSupertype().hasQualifiedName("java.util.stream", "Stream")
		and ma.getQualifier() = node1.asExpr()
		and ma = node2.asExpr()
		)
	}
}


class HashSet extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(ClassInstanceExpr ctor|
		ctor.getConstructedType().getASourceSupertype().hasQualifiedName("java.util", "HashSet")
		and ctor.getNumArgument() = 1
		and ctor.getArgument(0) = node1.asExpr()
		and ctor = node2.asExpr()
		)
	}
}


class MyTaintTrackingConfig extends TaintTracking::Configuration {
	MyTaintTrackingConfig() { this = "MyTaintTrackingConfig" }
	override predicate isSource(DataFlow::Node source) { 
		exists(ConstraintValidatorisValidMethod im|
			source.asParameter() = im.getParameter(0)
		)
	}

	override predicate isSink(DataFlow::Node sink) { 
		exists(MethodAccess ma|
		ma.getMethod() instanceof ConstraintValidatorContextBuildTemplate
		and ma.getAnArgument() = sink.asExpr()
		)
	}
	override int explorationLimit() {result =  10} 
}

from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"

// from MyTaintTrackingConfig cfg, ConstraintValidatorisValidMethod im, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
// where
// 	cfg.hasPartialFlow(source, sink, _) and
//   source.getNode().asParameter() = im.getParameter(0)
// select sink, source, sink, "Partial flow from unsanitized user data"
