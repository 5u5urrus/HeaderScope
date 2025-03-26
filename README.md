
# HeaderScope

**HeaderGuard** is the current tool: https://headerguard.com. HeaderScope was a baby, which grew into the HeaderGuard you can find at that address. 

**HeaderScope** is a straightforward tool designed to analyze and report on the security configurations of HTTP headers. It checks for best practices and common configuration errors, making it easier to enhance the security of your website.

## Features

- **Security Checks**: Analyzes HTTP headers for common security best practices.
- **Flexibility**: Works with headers from both live websites and local files.
- **User-Friendly Reports**: Provides clear, concise feedback on header configurations, indicating both successes and potential improvements.

## Installation

Clone the repository using Git:

```bash
git clone https://github.com/5u5urrus/headerscope.git
cd headerscope
```

## Usage

To use HeaderScope, you can either specify a URL or a local file from which to read HTTP headers:

### Analyzing headers from a URL:

```bash
python headerscope.py --url https://example.com
```
### Analyzing headers from a local file:

```bash
python headerscope.py --file ./path/to/headers.txt
```

### Sample Output

<img width="524" alt="headerscope" src="https://github.com/5u5urrus/HeaderScope/assets/165041037/be969744-e742-4732-9bae-f54ae611d206">

## Contributing

Contributions to HeaderScope are welcome! Please fork the repository and submit pull requests with any enhancements, bug fixes, or improvements you develop.

## FAQs

**Q: How is HeaderScope different from other similar tools**

A: HeaderScope does not simply check for the presence of the security headers, it checks their values too, catching any security issues. More importantly, HeaderScope is highly configurable, you can fill it with keywords that security headers should and should not contain - this makes the tool potentially highly effective.

**Q: Does it work with all web servers?**

A: HeaderScope can analyze headers from any web server, as long as the server is accessible and returns HTTP headers.

## License

Distributed under the MIT License. See `LICENSE` for more information.
