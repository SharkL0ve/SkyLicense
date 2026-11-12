package cn.sky.skylicense.resource;

import lombok.Data;

@Data
public class MethodInfo {
	String className;
	String methodName;
	String methodDesc;
	char type;
}
