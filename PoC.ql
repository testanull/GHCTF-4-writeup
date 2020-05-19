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

class ConstraintValidatorContextBuildTemplateMethod extends Method{
	ConstraintValidatorContextBuildTemplateMethod(){
		this.hasName("buildConstraintViolationWithTemplate") and this.getDeclaringType().hasName("ConstraintValidatorContext")
	}
}

class InterpolationHelperMethod extends Method{
	InterpolationHelperMethod(){
		this.hasName("escapeMessageParameter")
		and this.getDeclaringType().hasQualifiedName("org.hibernate.validator.internal.engine.messageinterpolation.util", "InterpolationHelper")
	}
}

class AbstractConstraintValidatorsanitizeMessageMethod extends Method{
	AbstractConstraintValidatorsanitizeMessageMethod(){
		this.hasName("sanitizeMessage")
		and this.getDeclaringType().getASourceSupertype*().hasQualifiedName("com.netflix.titus.common.model.sanitizer.internal", "AbstractConstraintValidator")
	}
}

class GetterTainted extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(MethodAccess ma, Method m, Field f|
			ma.getMethod() = m
			and m.(GetterMethod).getField() = f
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

class ExceptionGetMessage extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(MethodAccess ma, Method m, TryStmt trystmt|
			ma.getMethod() = m
			and m.hasName("getMessage")
			and m.hasNoParameters()
			and m.getDeclaringType().getASourceSupertype*().hasQualifiedName("java.lang", "Throwable")
			and ma.getEnclosingStmt().getParent*() = trystmt.getACatchClause()
			and ma.getQualifier() = node1.asExpr()
			and ma = node2.asExpr()
		)
	}
}

class ExceptionToCatchClause extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(MethodAccess ma, Method m, TryStmt trystmt|
		trystmt.getACatchClause().getVariable() = node1.asExpr()
		and ma.getMethod() = m
		and ma.getEnclosingStmt().getParent*() = trystmt.getACatchClause()
		and m.hasName("getMessage")
		and ma.getQualifier() = node2.asExpr()
		)
	}
}

class TryCatch extends TaintTracking::AdditionalTaintStep{
	override predicate step(DataFlow::Node node1, DataFlow::Node node2){
		exists(Call call, TryStmt trystmt|
			(
				call instanceof ClassInstanceExpr
				or call instanceof MethodAccess
			) and (
				call.getEnclosingStmt().getParent*() = trystmt.getBlock()
				and trystmt.getACatchClause().getVariable() = node2.asExpr()
				and call.getAnArgument() = node1.asExpr()
			)
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
	override predicate isSanitizer(DataFlow::Node node) {
		exists(Method m |
		(m instanceof InterpolationHelperMethod
		or m instanceof AbstractConstraintValidatorsanitizeMessageMethod
		)
		and node.getEnclosingCallable() = m
		)
	}
	override predicate isSink(DataFlow::Node sink) { 
		exists(MethodAccess ma|
		ma.getMethod() instanceof ConstraintValidatorContextBuildTemplateMethod
		and ma.getAnArgument() = sink.asExpr()
		)
	}
	override int explorationLimit() {result =  10} 
}

predicate checkMessageInterpolator(){
	exists(MethodAccess ma, Method m|
	m.hasName("messageInterpolator")
	and m.getDeclaringType().getASourceSupertype*().hasQualifiedName("javax.validation", "ValidatorContext")
	and ma.getMethod() = m
	and ma.getAnArgument().getType().hasName("ParameterMessageInterpolator")
	)
}


from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where not checkMessageInterpolator() and cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"

// from MyTaintTrackingConfig cfg, ConstraintValidatorisValidMethod im, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
// where
// 	cfg.hasPartialFlow(source, sink, _) and
//   source.getNode().asParameter() = im.getParameter(0)
// select sink, source, sink, "Partial flow from unsanitized user data"
