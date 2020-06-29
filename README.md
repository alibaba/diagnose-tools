# diagnose-tools

1､快速上手

  建议在 Centos 7.5/7.6 版本中进行实验。

  第一步、使用如下命令clone代码：

    git clone https://github.com/alibaba/diagnose-tools.git
    
  第二步、在diagnose-tools目录中运行如下命令初始化编译环境：
  
    make devel        # 安装编译过程中需要的包
    
    make deps         # 编译依赖库，目前主要是编译java agent，以支持用户态java符号表解析
    
  第三步、编译工具：
  
    make
    
    这一步实际上会完成rpm的安装，你也可以用如下命令分别完成相应的工作：
    
    make module       # 编译内核模块
    
    make tools        # 编译用户态命令行工具
    
    make java_agent   # 编译java agent
    
    make pkg          # 制作rpm安装包
    
  第四步、测试
  
    make test
    
  不清楚的地方，加我的微信：linux-kernel
