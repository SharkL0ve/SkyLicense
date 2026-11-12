package cn.sky.skylicense.resource;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Setter
@Getter
public class ByteCode {
	private String className;
	private byte[] code;
	private boolean keep = false;
}
