package cn.sky.skylicense.resource;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Data
@Setter
@Getter
public class EntryInfo {
	public String Name;
	public String Version;
	public String EntryClass;
	public String EntryPoint;
	/** Retained only so legacy settings.yml files remain loadable; protocol v4 ignores it. */
	@Deprecated
	public boolean InfPort;
	public List<String> KeepClasses;

	public String getEntryClass() {
		return this.EntryClass.replace(".", "/");
	}

}
