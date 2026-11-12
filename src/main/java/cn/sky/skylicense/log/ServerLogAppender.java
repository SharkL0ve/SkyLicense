

package cn.sky.skylicense.log;

import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.appender.AbstractOutputStreamAppender;
import org.apache.logging.log4j.core.appender.OutputStreamManager;
import org.apache.logging.log4j.core.config.Property;

import java.io.Serializable;

public class ServerLogAppender extends AbstractOutputStreamAppender<OutputStreamManager> {
	protected ServerLogAppender(String name, Layout<? extends Serializable> layout, Filter filter, boolean ignoreExceptions, boolean immediateFlush, Property[] properties, OutputStreamManager manager) {
		super(name, layout, filter, ignoreExceptions, immediateFlush, properties, manager);
	}
}
