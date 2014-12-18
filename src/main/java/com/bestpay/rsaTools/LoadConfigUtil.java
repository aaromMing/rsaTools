package com.bestpay.rsaTools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/**
 * 加载配置文件.
 * @author zhouyanjie.
 */
public final class LoadConfigUtil {
	
	
	/**
	 * 属性文件全名"config/XXXX.properties".
	 */
	private static final String PFILE = "config/rsakey.properties";

	/**
	 * 配置文件.
	 */
	private Properties properties = null;

	/**
	 * 对应属性文件.
	 */
	private File file = null;

	/**
	 * 属性最后修改日期.
	 */
	private long lastModifiedTime = 0;

	/**
	 * 单例.
	 */
	private static LoadConfigUtil instance = new LoadConfigUtil();

	/**
	 * 私有构造方法.
	 */
	private LoadConfigUtil() {
		file = new File(PFILE);
		lastModifiedTime = file.lastModified();
		if (lastModifiedTime == 0) {
			System.err.println(PFILE + "配置文件不存在");
		}
		try {
			properties = new Properties();
			properties.load(new FileInputStream(PFILE));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 获得单例.
	 * 
	 * @return instance.
	 */
	public static synchronized LoadConfigUtil getInstance() {
		return instance;
	}
	
	public static void main(String[] args) {
		String rsaModulu = getInstance().getConfigItem("RSA_MODULU", "");
		System.out.println(rsaModulu);
    }
	
	public String getConfigItem(String name) {
		return getConfigItem(name, "");
	}
	
	/**
	 * 获得文件属性.
	 * @param name
	 *            参数名.
	 * @param defaultVal
	 *            默认值.
	 * @return 属性值.
	 */
	public String getConfigItem(String name, String defaultVal) {
		long newTime = file.lastModified();
		// 检查属性文件是否被修改 ture则重新读取文件
		if (newTime == 0) {
			if (lastModifiedTime == 0) {
				System.err.println(PFILE + "配置文件不存在");
			} else {
				System.err.println(PFILE + "配置文件被删除");
			}
			return defaultVal;
		} else if (newTime > lastModifiedTime) {
			properties.clear();
			try {
				properties.load(new FileInputStream(PFILE));
				lastModifiedTime = newTime;
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		String val = properties.getProperty(name);
		if (val == null) {
			return defaultVal;
		} else {
			return val;
		}

	}

}
