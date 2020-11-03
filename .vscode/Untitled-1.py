import turtle as t
x1 = eval(input("Please input x1:"))
y1 = eval(input("Please input y1:"))
x2 = eval(input("Please input x2:"))
y2 = eval(input("Please input y2:"))

dist = pow(pow(x1-x2,2)+pow(y1-y2,2),0.5)
print("Two dots' distance is:",dist)

t.setup(800,800)
t.pensize(1)
t.pencolor("purple")
t.penup()
t.goto(x1,y1)
t.pendown()
t.goto(x2,y2)

t.penup()
t.pencolor("red")
t.goto(abs(x1-x2)/2,abs(y1-y2)/2)
t.right(90)
t.fd(dist/10)
t.write(dist)
t.done()