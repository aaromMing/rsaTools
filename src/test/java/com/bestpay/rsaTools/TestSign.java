package com.bestpay.rsaTools;


public class TestSign {


	public static void main(String[] args) {
	    TestSign signUtil = new TestSign();
	    BeanDemo beanDemo = signUtil.new BeanDemo();
	    beanDemo.setId("1234");
	    beanDemo.setName("小米");
	    String signature = RSAUtil.getSign(beanDemo);
	    boolean verifySign = RSAUtil.verifySign("id=1234&name=小米", signature);
	    System.out.println(verifySign);
    }
	
	
	class BeanDemo {
		
		private String id;
		private String name;

		public String getId() {
			return id;
		}

		public void setId(String id) {
			this.id = id;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

	}

}
