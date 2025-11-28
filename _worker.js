let DoH = "one.one.one.one";
const jsonDoH = `https://${DoH}/resolve`;
const dnsDoH = `https://${DoH}/dns-query`;
let DoH路径 = "dns-query";
export default {
	async fetch(request, env) {
		if (env.DOH) {
			DoH = env.DOH;
			const match = DoH.match(/:\/\/([^\/]+)/);
			if (match) {
				DoH = match[1];
			}
		}
		DoH路径 = env.PATH || env.TOKEN || DoH路径;
		if (DoH路径.includes("/")) DoH路径 = DoH路径.split("/")[1];
		const url = new URL(request.url);
		const path = url.pathname;
		const hostname = url.hostname;
		if (request.method === "OPTIONS") {
			return new Response(null, {
				headers: {
					"Access-Control-Allow-Origin": "*",
					"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
					"Access-Control-Allow-Headers": "*",
					"Access-Control-Max-Age": "86400",
				},
			});
		}
		if (path === `/${DoH路径}`) {
			return await DOHRequest(request);
		}
		if (path === "/ip-info") {
			if (env.TOKEN) {
				const token = url.searchParams.get("token");
				if (token != env.TOKEN) {
					return new Response(
						JSON.stringify(
							{
								status: "error",
								message: "Token不正确",
								code: "AUTH_FAILED",
								timestamp: new Date().toISOString(),
							},
							null,
							4
						),
						{
							status: 403,
							headers: {
								"content-type":
									"application/json; charset=UTF-8",
								"Access-Control-Allow-Origin": "*",
							},
						}
					);
				}
			}
			const ip =
				url.searchParams.get("ip") ||
				request.headers.get("CF-Connecting-IP");
			if (!ip) {
				return new Response(
					JSON.stringify(
						{
							status: "error",
							message: "IP参数未提供",
							code: "MISSING_PARAMETER",
							timestamp: new Date().toISOString(),
						},
						null,
						4
					),
					{
						status: 400,
						headers: {
							"content-type": "application/json; charset=UTF-8",
							"Access-Control-Allow-Origin": "*",
						},
					}
				);
			}
			try {
				const response = await fetch(
					`http://ip-api.com/json/${ip}?lang=zh-CN`
				);

				if (!response.ok) {
					throw new Error(`HTTP error: ${response.status}`);
				}
				const data = await response.json();
				data.timestamp = new Date().toISOString();
				return new Response(JSON.stringify(data, null, 4), {
					headers: {
						"content-type": "application/json; charset=UTF-8",
						"Access-Control-Allow-Origin": "*",
					},
				});
			} catch (error) {
				console.error("IP查询失败:", error);
				return new Response(
					JSON.stringify(
						{
							status: "error",
							message: `IP查询失败: ${error.message}`,
							code: "API_REQUEST_FAILED",
							query: ip,
							timestamp: new Date().toISOString(),
							details: {
								errorType: error.name,
								stack: error.stack
									? error.stack.split("\n")[0]
									: null,
							},
						},
						null,
						4
					),
					{
						status: 500,
						headers: {
							"content-type": "application/json; charset=UTF-8",
							"Access-Control-Allow-Origin": "*",
						},
					}
				);
			}
		}
		if (url.searchParams.has("doh")) {
			const domain =
				url.searchParams.get("domain") ||
				url.searchParams.get("name") ||
				"www.google.com";
			const doh = url.searchParams.get("doh") || dnsDoH;
			const type = url.searchParams.get("type") || "all";
			if (doh.includes(url.host)) {
				return await handleLocalDohRequest(domain, type, hostname);
			}
			try {
				if (type === "all") {
					const ipv4Result = await queryDns(doh, domain, "A");
					const ipv6Result = await queryDns(doh, domain, "AAAA");
					const nsResult = await queryDns(doh, domain, "NS");
					const combinedResult = {
						Status:
							ipv4Result.Status ||
							ipv6Result.Status ||
							nsResult.Status,
						TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
						RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
						RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
						AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
						CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
						Question: [],
						Answer: [
							...(ipv4Result.Answer || []),
							...(ipv6Result.Answer || []),
						],
						ipv4: {
							records: ipv4Result.Answer || [],
						},
						ipv6: {
							records: ipv6Result.Answer || [],
						},
						ns: {
							records: [],
						},
					};
					if (ipv4Result.Question) {
						if (Array.isArray(ipv4Result.Question)) {
							combinedResult.Question.push(
								...ipv4Result.Question
							);
						} else {
							combinedResult.Question.push(ipv4Result.Question);
						}
					}
					if (ipv6Result.Question) {
						if (Array.isArray(ipv6Result.Question)) {
							combinedResult.Question.push(
								...ipv6Result.Question
							);
						} else {
							combinedResult.Question.push(ipv6Result.Question);
						}
					}
					if (nsResult.Question) {
						if (Array.isArray(nsResult.Question)) {
							combinedResult.Question.push(...nsResult.Question);
						} else {
							combinedResult.Question.push(nsResult.Question);
						}
					}
					const nsRecords = [];
					if (nsResult.Answer && nsResult.Answer.length > 0) {
						nsResult.Answer.forEach((record) => {
							if (record.type === 2) {
								nsRecords.push(record);
							}
						});
					}
					if (nsResult.Authority && nsResult.Authority.length > 0) {
						nsResult.Authority.forEach((record) => {
							if (record.type === 2 || record.type === 6) {
								nsRecords.push(record);
								combinedResult.Answer.push(record);
							}
						});
					}
					combinedResult.ns.records = nsRecords;
					return new Response(
						JSON.stringify(combinedResult, null, 2),
						{
							headers: {
								"content-type":
									"application/json; charset=UTF-8",
							},
						}
					);
				} else {
					const result = await queryDns(doh, domain, type);
					return new Response(JSON.stringify(result, null, 2), {
						headers: {
							"content-type": "application/json; charset=UTF-8",
						},
					});
				}
			} catch (err) {
				console.error("DNS 查询失败:", err);
				return new Response(
					JSON.stringify(
						{
							error: `DNS 查询失败: ${err.message}`,
							doh: doh,
							domain: domain,
							stack: err.stack,
						},
						null,
						2
					),
					{
						headers: {
							"content-type": "application/json; charset=UTF-8",
						},
						status: 500,
					}
				);
			}
		}
		if (env.URL302) return Response.redirect(env.URL302, 302);
		else if (env.URL) {
			if (env.URL.toString().toLowerCase() == "nginx") {
				return new Response(await nginx(), {
					headers: {
						"Content-Type": "text/html; charset=UTF-8",
					},
				});
			} else return await 代理URL(env.URL, url);
		} else return await HTML();
	},
};
async function queryDns(dohServer, domain, type) {
	const dohUrl = new URL(dohServer);
	dohUrl.searchParams.set("name", domain);
	dohUrl.searchParams.set("type", type);
	const fetchOptions = [
		{
			headers: { Accept: "application/dns-json" },
		},
		{
			headers: {},
		},
		{
			headers: { Accept: "application/json" },
		},
		{
			headers: {
				Accept: "application/dns-json",
				"User-Agent": "Mozilla/5.0 DNS Client",
			},
		},
	];
	let lastError = null;
	for (const options of fetchOptions) {
		try {
			const response = await fetch(dohUrl.toString(), options);
			if (response.ok) {
				const contentType = response.headers.get("content-type") || "";
				if (
					contentType.includes("json") ||
					contentType.includes("dns-json")
				) {
					return await response.json();
				} else {
					const textResponse = await response.text();
					try {
						return JSON.parse(textResponse);
					} catch (jsonError) {
						throw new Error(
							`无法解析响应为JSON: ${
								jsonError.message
							}, 响应内容: ${textResponse.substring(0, 100)}`
						);
					}
				}
			}
			const errorText = await response.text();
			lastError = new Error(
				`DoH 服务器返回错误 (${response.status}): ${errorText.substring(
					0,
					200
				)}`
			);
		} catch (err) {
			lastError = err;
		}
	}
	throw lastError || new Error("无法完成 DNS 查询");
}
async function handleLocalDohRequest(domain, type, hostname) {
	try {
		if (type === "all") {
			const ipv4Promise = queryDns(dnsDoH, domain, "A");
			const ipv6Promise = queryDns(dnsDoH, domain, "AAAA");
			const nsPromise = queryDns(dnsDoH, domain, "NS");
			const [ipv4Result, ipv6Result, nsResult] = await Promise.all([
				ipv4Promise,
				ipv6Promise,
				nsPromise,
			]);
			const nsRecords = [];
			if (nsResult.Answer && nsResult.Answer.length > 0) {
				nsRecords.push(
					...nsResult.Answer.filter((record) => record.type === 2)
				);
			}
			if (nsResult.Authority && nsResult.Authority.length > 0) {
				nsRecords.push(
					...nsResult.Authority.filter(
						(record) => record.type === 2 || record.type === 6
					)
				);
			}
			const combinedResult = {
				Status:
					ipv4Result.Status || ipv6Result.Status || nsResult.Status,
				TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
				RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
				RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
				AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
				CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
				Question: [
					...(ipv4Result.Question || []),
					...(ipv6Result.Question || []),
					...(nsResult.Question || []),
				],
				Answer: [
					...(ipv4Result.Answer || []),
					...(ipv6Result.Answer || []),
					...nsRecords,
				],
				ipv4: {
					records: ipv4Result.Answer || [],
				},
				ipv6: {
					records: ipv6Result.Answer || [],
				},
				ns: {
					records: nsRecords,
				},
			};
			return new Response(JSON.stringify(combinedResult, null, 2), {
				headers: {
					"content-type": "application/json; charset=UTF-8",
					"Access-Control-Allow-Origin": "*",
				},
			});
		} else {
			const result = await queryDns(dnsDoH, domain, type);
			return new Response(JSON.stringify(result, null, 2), {
				headers: {
					"content-type": "application/json; charset=UTF-8",
					"Access-Control-Allow-Origin": "*",
				},
			});
		}
	} catch (err) {
		console.error("DoH 查询失败:", err);
		return new Response(
			JSON.stringify(
				{
					error: `DoH 查询失败: ${err.message}`,
					stack: err.stack,
				},
				null,
				2
			),
			{
				headers: {
					"content-type": "application/json; charset=UTF-8",
					"Access-Control-Allow-Origin": "*",
				},
				status: 500,
			}
		);
	}
}
async function DOHRequest(request) {
	const { method, headers, body } = request;
	const UA = headers.get("User-Agent") || "DoH Client";
	const url = new URL(request.url);
	const { searchParams } = url;
	try {
		if (method === "GET" && !url.search) {
			return new Response("Bad Request", {
				status: 400,
				headers: {
					"Content-Type": "text/plain; charset=utf-8",
					"Access-Control-Allow-Origin": "*",
				},
			});
		}
		let response;

		if (method === "GET" && searchParams.has("name")) {
			const searchDoH = searchParams.has("type")
				? url.search
				: url.search + "&type=A";
			response = await fetch(dnsDoH + searchDoH, {
				headers: {
					Accept: "application/dns-json",
					"User-Agent": UA,
				},
			});
			if (!response.ok)
				response = await fetch(jsonDoH + searchDoH, {
					headers: {
						Accept: "application/dns-json",
						"User-Agent": UA,
					},
				});
		} else if (method === "GET") {
			response = await fetch(dnsDoH + url.search, {
				headers: {
					Accept: "application/dns-message",
					"User-Agent": UA,
				},
			});
		} else if (method === "POST") {
			response = await fetch(dnsDoH, {
				method: "POST",
				headers: {
					Accept: "application/dns-message",
					"Content-Type": "application/dns-message",
					"User-Agent": UA,
				},
				body: body,
			});
		} else {
			return new Response(
				"不支持的请求格式: DoH请求需要包含name或dns参数，或使用POST方法",
				{
					status: 400,
					headers: {
						"Content-Type": "text/plain; charset=utf-8",
						"Access-Control-Allow-Origin": "*",
					},
				}
			);
		}
		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(
				`DoH 返回错误 (${response.status}): ${errorText.substring(
					0,
					200
				)}`
			);
		}
		const responseHeaders = new Headers(response.headers);
		responseHeaders.set("Access-Control-Allow-Origin", "*");
		responseHeaders.set(
			"Access-Control-Allow-Methods",
			"GET, POST, OPTIONS"
		);
		responseHeaders.set("Access-Control-Allow-Headers", "*");
		if (method === "GET" && searchParams.has("name")) {
			responseHeaders.set("Content-Type", "application/json");
		}
		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers: responseHeaders,
		});
	} catch (error) {
		console.error("DoH 请求处理错误:", error);
		return new Response(
			JSON.stringify(
				{
					error: `DoH 请求处理错误: ${error.message}`,
					stack: error.stack,
				},
				null,
				4
			),
			{
				status: 500,
				headers: {
					"Content-Type": "application/json",
					"Access-Control-Allow-Origin": "*",
				},
			}
		);
	}
}
async function HTML() {
	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS-Resolver</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="icon"
    href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg"
    type="image/x-icon">
  <style>
    :root {
      --primary-color: #00bcd4;
      --primary-dark: #008ba3;
      --primary-light: #62efff;
      --bg-color: #f9fcff;
      --text-color: #333333;
      --card-bg: rgba(255, 255, 255, 0.85);
      --card-border: rgba(0, 188, 212, 0.3);
      --input-bg: rgba(255, 255, 255, 0.9);
      --shadow-color: rgba(0, 0, 0, 0.1);
      --soa-text-color: #333333;
      
      --color-a: rgba(25, 118, 210, 0.15);
      --color-aaaa: rgba(27, 94, 32, 0.15);
      --color-cname: rgba(155, 89, 182, 0.15);
      --color-ns: rgba(241, 196, 15, 0.15);
      --color-soa: rgba(230, 126, 34, 0.15);
      --color-other: rgba(149, 165, 166, 0.15);
      
      --type-a: #1976d2;
      --type-aaaa: #1b5e20;
      --type-cname: #9b59b6;
      --type-ns: #f1c40f;
      --type-soa: #e67e22;
      --type-other: #95a5a6;
    }

    .dark-mode {
      --primary-color: #00bcd4;
      --primary-dark: #008ba3;
      --primary-light: #62efff;
      --bg-color: #000000;
      --text-color: #ffffff;
      --card-bg: rgba(30, 30, 30, 0.9);
      --card-border: rgba(0, 188, 212, 0.5);
      --input-bg: rgba(50, 50, 50, 0.9);
      --shadow-color: rgba(0, 0, 0, 0.3);
      --soa-text-color: #ffffff;
      
      --color-a: rgba(25, 118, 210, 0.25);
      --color-aaaa: rgba(27, 94, 32, 0.25);
      --color-cname: rgba(155, 89, 182, 0.25);
      --color-ns: rgba(241, 196, 15, 0.25);
      --color-soa: rgba(230, 126, 34, 0.25);
      --color-other: rgba(149, 165, 166, 0.25);
      
      --type-a: #64b5f6;
      --type-aaaa: #81c784;
      --type-cname: #ce93d8;
      --type-ns: #fff59d;
      --type-soa: #ffb74d;
      --type-other: #b0bec5;
    }

    html, body {
      height: 100%;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      min-height: 100vh;
      padding: 0;
      margin: 0;
      line-height: 1.6;
      background-color: var(--bg-color);
      background-size: cover;
      background-position: center center;
      background-repeat: no-repeat;
      background-attachment: fixed;
      padding: 30px 20px;
      box-sizing: border-box;
      color: var(--text-color);
      transition: all 0.3s ease;
    }

    .page-wrapper {
      width: 100%;
      max-width: 800px;
      margin: 0 auto;
    }

    .container {
      width: 100%;
      max-width: 800px;
      margin: 20px auto;
      background-color: var(--card-bg);
      border-radius: 16px;
      box-shadow: 0 8px 32px var(--shadow-color);
      padding: 30px;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid var(--card-border);
      transition: all 0.3s ease;
    }

    h1 {
      color: var(--primary-color);
      font-weight: 600;
      text-shadow: none;
    }

    .card {
      margin-bottom: 20px;
      border: none;
      box-shadow: 0 2px 10px var(--shadow-color);
      background-color: var(--card-bg);
      backdrop-filter: blur(5px);
      -webkit-backdrop-filter: blur(5px);
      transition: all 0.3s ease;
    }

    .card-header {
      background-color: rgba(0, 188, 212, 0.1);
      font-weight: 600;
      padding: 12px 20px;
      border-bottom: none;
      color: var(--text-color);
      transition: all 0.3s ease;
    }

    .form-label {
      font-weight: 500;
      margin-bottom: 8px;
      color: var(--text-color);
    }

    .form-select,
    .form-control {
      border-radius: 6px;
      padding: 10px;
      border: 1px solid var(--card-border);
      background-color: var(--input-bg);
      color: var(--text-color);
      transition: all 0.3s ease;
    }

    .form-select:focus,
    .form-control:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 0.2rem rgba(0, 188, 212, 0.25);
    }

    .btn-primary {
      background-color: var(--primary-color);
      border: none;
      border-radius: 6px;
      padding: 10px 20px;
      font-weight: 500;
      transition: all 0.2s ease;
    }

    .btn-primary:hover {
      background-color: var(--primary-dark);
      transform: translateY(-1px);
    }

    .btn-outline-primary {
      color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .btn-outline-primary:hover {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
      color: white;
    }

    .btn-outline-secondary {
      color: var(--text-color);
      border-color: #6c757d;
    }

    .btn-outline-secondary:hover {
      background-color: #6c757d;
      border-color: #6c757d;
      color: white;
    }

    .btn-toggle {
      background-color: var(--primary-color);
      color: white;
      border: none;
      border-radius: 6px;
      padding: 10px 15px;
      font-weight: 500;
      transition: all 0.2s ease;
    }

    .btn-toggle:hover {
      background-color: var(--primary-dark);
      transform: translateY(-1px);
    }

    pre {
      background-color: rgba(0, 188, 212, 0.1);
      padding: 15px;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      white-space: pre-wrap;
      word-break: break-all;
      font-family: Consolas, Monaco, 'Andale Mono', monospace;
      font-size: 14px;
      max-height: 400px;
      overflow: auto;
      color: var(--text-color);
      transition: all 0.3s ease;
    }

    .loading {
      display: none;
      text-align: center;
      padding: 20px 0;
    }

    .loading-spinner {
      border: 4px solid rgba(0, 0, 0, 0.1);
      border-left: 4px solid var(--primary-color);
      border-radius: 50%;
      width: 30px;
      height: 30px;
      animation: spin 1s linear infinite;
      margin: 0 auto 10px;
    }

    .badge {
      margin-left: 5px;
      font-size: 11px;
      vertical-align: middle;
    }

    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    .footer {
      margin-top: 30px;
      text-align: center;
      color: rgba(255, 255, 255, 0.9);
      font-size: 14px;
    }

    .beian-info {
      text-align: center;
      font-size: 13px;
      color: var(--text-color);
    }

    .beian-info a {
      color: var(--primary-color);
      text-decoration: none;
      border-bottom: 1px dashed var(--primary-color);
      padding-bottom: 2px;
    }

    .beian-info a:hover {
      border-bottom-style: solid;
    }

    @media (max-width: 576px) {
      .container {
        padding: 20px;
      }
    }

    .error-message {
      color: #e63e00;
      margin-top: 10px;
    }

    .success-message {
      color: var(--primary-color);
    }

    .nav-tabs .nav-link {
      border-top-left-radius: 6px;
      border-top-right-radius: 6px;
      padding: 8px 16px;
      font-weight: 500;
      color: var(--text-color);
      background-color: rgba(0, 188, 212, 0.1);
      border: 1px solid var(--card-border);
      margin-right: 5px;
    }

    .nav-tabs .nav-link.active {
      background-color: var(--card-bg);
      border-bottom-color: var(--card-bg);
      color: var(--primary-color);
    }

    .tab-content {
      background-color: var(--card-bg);
      border-radius: 0 0 6px 6px;
      padding: 15px;
      border: 1px solid var(--card-border);
      border-top: none;
      transition: all 0.3s ease;
    }

    .result-summary {
      color: var(--text-color);
      margin-bottom: 15px;
      padding: 10px;
      background-color: rgba(0, 188, 212, 0.1);
      border-radius: 6px;
    }

    .result-summary strong {
      color: var(--text-color);
    }

    .ip-record {
      display: table;
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 10px;
      border-radius: 6px;
      overflow: hidden;
      border: 1px solid var(--card-border);
      transition: all 0.3s ease;
    }

    .record-a {
      background-color: var(--color-a);
      border-left: 4px solid var(--type-a);
    }
    
    .record-aaaa {
      background-color: var(--color-aaaa);
      border-left: 4px solid var(--type-aaaa);
    }
    
    .record-cname {
      background-color: var(--color-cname);
      border-left: 4px solid var(--type-cname);
    }
    
    .record-ns {
      background-color: var(--color-ns);
      border-left: 4px solid var(--type-ns);
    }
    
    .record-soa {
      background-color: var(--color-soa);
      border-left: 4px solid var(--type-soa);
    }
    
    .record-other {
      background-color: var(--color-other);
      border-left: 4px solid var(--type-other);
    }

    .ip-record-row {
      display: table-row;
    }

    .ip-record-cell {
      display: table-cell;
      padding: 8px 10px;
      vertical-align: middle;
      border-bottom: 1px solid rgba(0, 0, 0, 0.05);
      color: var(--text-color);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 0;
    }

    .ip-record-cell:first-child {
      width: 30%;
      font-weight: 600;
      color: var(--primary-dark);
    }

    .ip-record-cell:last-child {
      width: 70%;
    }

    .ip-record-row:last-child .ip-record-cell {
      border-bottom: none;
    }

    .ip-address {
      font-family: monospace;
      font-weight: 600;
      color: var(--text-color);
      cursor: pointer;
      position: relative;
      transition: color 0.2s ease;
      display: inline-block;
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .ip-address:hover {
      color: var(--primary-color);
    }

    .ip-address:after {
      content: '';
      position: absolute;
      left: 100%;
      top: 0;
      opacity: 0;
      white-space: nowrap;
      font-size: 12px;
      color: var(--primary-color);
      transition: opacity 0.3s ease;
      font-family: 'Segoe UI', sans-serif;
      font-weight: normal;
    }

    .ip-address.copied:after {
      content: '已复制';
      opacity: 1;
    }

    .geo-country {
      color: var(--primary-dark);
      font-weight: 500;
      padding: 2px 6px;
      background-color: rgba(0, 188, 212, 0.1);
      border-radius: 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
      display: inline-block;
    }

    .geo-as {
      color: var(--primary-color);
      padding: 2px 6px;
      background-color: rgba(0, 188, 212, 0.1);
      border-radius: 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
      display: inline-block;
    }

    .geo-blocked {
      color: #ffffff;
      background-color: #dc3545;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 600;
      display: inline-block;
      animation: pulse-red 2s infinite;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
    }

    .geo-loading {
      color: var(--text-color);
      font-style: italic;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
      display: inline-block;
    }

    .ttl-info {
      color: var(--primary-dark);
      font-weight: 500;
    }

    .record-type {
      font-weight: 500;
      padding: 2px 6px;
      border-radius: 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
      display: inline-block;
    }

    .type-a {
      color: var(--type-a);
      background-color: rgba(25, 118, 210, 0.1);
    }

    .type-aaaa {
      color: var(--type-aaaa);
      background-color: rgba(27, 94, 32, 0.1);
    }

    .type-cname {
      color: var(--type-cname);
      background-color: rgba(155, 89, 182, 0.1);
    }

    .type-ns {
      color: var(--type-ns);
      background-color: rgba(241, 196, 15, 0.1);
    }

    .type-soa {
      color: var(--type-soa);
      background-color: rgba(230, 126, 34, 0.1);
    }

    .type-other {
      color: var(--type-other);
      background-color: rgba(149, 165, 166, 0.1);
    }

    @keyframes pulse-red {
      0% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7); }
      70% { box-shadow: 0 0 0 10px rgba(220, 53, 69, 0); }
      100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); }
    }

    .copy-link {
      color: var(--primary-color);
      text-decoration: none;
      border-bottom: 1px dashed var(--primary-color);
      padding-bottom: 2px;
      cursor: pointer;
      position: relative;
    }

    .copy-link:hover {
      border-bottom-style: solid;
    }

    .copy-link:after {
      content: '';
      position: absolute;
      top: 0;
      right: -65px;
      opacity: 0;
      white-space: nowrap;
      color: var(--primary-color);
      font-size: 12px;
      transition: opacity 0.3s ease;
    }

    .copy-link.copied:after {
      content: '已复制';
      opacity: 1;
    }

    .soa-details {
      color: var(--soa-text-color);
    }

    .soa-details div {
      color: var(--soa-text-color);
    }

    .soa-details strong {
      color: var(--soa-text-color);
    }

    @media (max-width: 768px) {
      .ip-record-cell:first-child {
        width: 35%;
      }
      
      .ip-record-cell:last-child {
        width: 65%;
      }
    }

    @media (max-width: 480px) {
      .ip-record-cell {
        padding: 6px 8px;
        font-size: 0.85em;
      }
      
      .ip-record-cell:first-child {
        width: 40%;
      }
      
      .ip-record-cell:last-child {
        width: 60%;
      }
      
      .geo-country, .geo-as, .geo-blocked {
        font-size: 0.8em;
        padding: 1px 4px;
      }
      
      .ttl-info {
        font-size: 0.8em;
      }
    }
  </style>
</head>

<body>
  <div class="container">
    <h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
    <div class="card">
      <div class="card-header">DNS 查询设置</div>
      <div class="card-body">
        <form id="resolveForm">
          <div class="mb-3">
            <label for="dohSelect" class="form-label">选择 DoH 地址:</label>
            <select id="dohSelect" class="form-select">
              <option value="current" selected id="currentDohOption">自动 (当前站点)</option>
              <option value="https://dns.alidns.com/resolve">https://dns.alidns.com/resolve (阿里)</option>
              <option value="https://sm2.doh.pub/dns-query">https://sm2.doh.pub/dns-query (腾讯)</option>
              <option value="https://doh.360.cn/resolve">https://doh.360.cn/resolve (360)</option>
              <option value="https://cloudflare-dns.com/dns-query">https://cloudflare-dns.com/dns-query (Cloudflare)</option>
              <option value="https://dns.google/resolve">https://dns.google/resolve (谷歌)</option>
              <option value="https://dns.adguard-dns.com/resolve">https://dns.adguard-dns.com/resolve (AdGuard)</option>
              <option value="https://dns.sb/dns-query">https://dns.sb/dns-query (DNS.SB)</option>
              <option value="https://zero.dns0.eu/">https://zero.dns0.eu (dns0.eu)</option>
              <option value="https://dns.nextdns.io">	https://dns.nextdns.io (NextDNS)</option>
              <option value="https://dns.rabbitdns.org/dns-query">https://dns.rabbitdns.org/dns-query (Rabbit DNS)</option>
              <option value="https://basic.rethinkdns.com/">https://basic.rethinkdns.com (RethinkDNS)</option>
              <option value="https://v.recipes/dns-query">https://v.recipes/dns-query (v.recipes DNS)</option>
              <option value="custom">自定义...</option>
            </select>
          </div>
          <div id="customDohContainer" class="mb-3" style="display:none;">
            <label for="customDoh" class="form-label">输入自定义 DoH 地址:</label>
            <input type="text" id="customDoh" class="form-control" placeholder="https://example.com/dns-query">
          </div>
          <div class="mb-3">
            <label for="domain" class="form-label">待解析域名:</label>
            <div class="input-group">
              <input type="text" id="domain" class="form-control" value="www.google.com"
                placeholder="输入域名，如 example.com">
              <button type="button" class="btn btn-outline-secondary" id="clearBtn">清除</button>
            </div>
          </div>
          <div class="d-flex gap-2">
            <button type="submit" class="btn btn-primary flex-grow-1">解析</button>
            <button type="button" class="btn btn-outline-primary" id="getJsonBtn">Get Json</button>
            <button type="button" class="btn btn-toggle" id="themeToggle">✨</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>解析结果</span>
        <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display: none;">复制结果</button>
      </div>
      <div class="card-body">
        <div id="loading" class="loading">
          <div class="loading-spinner"></div>
          <p>正在查询中，请稍候...</p>
        </div>

        <div id="resultContainer" style="display: none;">
          <ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button"
                role="tab">IPv4</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button"
                role="tab">IPv6</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button" role="tab">NS</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button"
                role="tab">JS</button>
            </li>
          </ul>
          <div class="tab-content" id="resultTabContent">
            <div class="tab-pane fade show active" id="ipv4" role="tabpanel" aria-labelledby="ipv4-tab">
              <div class="result-summary" id="ipv4Summary"></div>
              <div id="ipv4Records"></div>
            </div>
            <div class="tab-pane fade" id="ipv6" role="tabpanel" aria-labelledby="ipv6-tab">
              <div class="result-summary" id="ipv6Summary"></div>
              <div id="ipv6Records"></div>
            </div>
            <div class="tab-pane fade" id="ns" role="tabpanel" aria-labelledby="ns-tab">
              <div class="result-summary" id="nsSummary"></div>
              <div id="nsRecords"></div>
            </div>
            <div class="tab-pane fade" id="raw" role="tabpanel" aria-labelledby="raw-tab">
              <pre id="result">等待查询...</pre>
            </div>
          </div>
        </div>

        <div id="errorContainer" style="display: none;">
          <pre id="errorMessage" class="error-message"></pre>
        </div>
      </div>
    </div>

    <div class="beian-info">
      <p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">https://<span
              id="currentDomain">...</span>/${DoH路径}</span></strong><br>基于 Cloudflare Workers 上游 ${DoH} 的 DoH (DNS over HTTPS)
        解析服务</p>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    const currentUrl = window.location.href;
    const currentHost = window.location.host;
    const currentProtocol = window.location.protocol;
    const currentDohPath = '${DoH路径}';
    const currentDohUrl = currentProtocol + '//' + currentHost + '/' + currentDohPath;

    let activeDohUrl = currentDohUrl;

    const 阻断IPv4 = [
      '104.21.16.1',
      '104.21.32.1',
      '104.21.48.1',
      '104.21.64.1',
      '104.21.80.1',
      '104.21.96.1',
      '104.21.112.1'
    ];

    const 阻断IPv6 = [
      '2606:4700:3030::6815:1001',
      '2606:4700:3030::6815:3001',
      '2606:4700:3030::6815:7001',
      '2606:4700:3030::6815:5001'
    ];

    function isBlockedIP(ip) {
      return 阻断IPv4.includes(ip) || 阻断IPv6.includes(ip);
    }

    function initTheme() {
      const theme = localStorage.getItem('theme') || 'light';
      const themeToggle = document.getElementById('themeToggle');
      
      if (theme === 'dark') {
        document.body.classList.add('dark-mode');
        themeToggle.textContent = '☀️';
      } else {
        document.body.classList.remove('dark-mode');
        themeToggle.textContent = '✨';
      }
    }

    function toggleTheme() {
      if (document.body.classList.contains('dark-mode')) {
        document.body.classList.remove('dark-mode');
        localStorage.setItem('theme', 'light');
        document.getElementById('themeToggle').textContent = '✨';
      } else {
        document.body.classList.add('dark-mode');
        localStorage.setItem('theme', 'dark');
        document.getElementById('themeToggle').textContent = '☀️';
      }
    }

    function updateActiveDohDisplay() {
      const dohSelect = document.getElementById('dohSelect');
      if (dohSelect.value === 'current') {
        activeDohUrl = currentDohUrl;
      }
    }

    updateActiveDohDisplay();

    document.getElementById('dohSelect').addEventListener('change', function () {
      const customContainer = document.getElementById('customDohContainer');
      customContainer.style.display = (this.value === 'custom') ? 'block' : 'none';

      if (this.value === 'current') {
        activeDohUrl = currentDohUrl;
      } else if (this.value !== 'custom') {
        activeDohUrl = this.value;
      }
    });

    document.getElementById('clearBtn').addEventListener('click', function () {
      document.getElementById('domain').value = '';
      document.getElementById('domain').focus();
    });

    document.getElementById('copyBtn').addEventListener('click', function () {
      const resultText = document.getElementById('result').textContent;
      navigator.clipboard.writeText(resultText).then(function () {
        const originalText = this.textContent;
        this.textContent = '已复制';
        setTimeout(() => {
          this.textContent = originalText;
        }, 2000);
      }.bind(this)).catch(function (err) {
        console.error('无法复制文本: ', err);
      });
    });

    function formatTTL(seconds) {
      seconds = Number(seconds);
      if (isNaN(seconds)) return '未知';
      
      if (seconds < 60) return seconds + '秒';
      if (seconds < 3600) return Math.floor(seconds / 60) + '分钟';
      if (seconds < 86400) return Math.floor(seconds / 3600) + '小时';
      if (seconds < 2592000) return Math.floor(seconds / 86400) + '天';
      if (seconds < 31536000) return Math.floor(seconds / 2592000) + '个月';
      return Math.floor(seconds / 31536000) + '年';
    }

    async function queryIpGeoInfo(ip) {
      try {
        const response = await fetch(\`./ip-info?ip=\${ip}&token=${DoH路径}\`);
            if (!response.ok) {
              throw new Error(\`HTTP 错误: \${response.status}\`);
            }
            return await response.json();
          } catch (error) {
            console.error('IP 地理位置查询失败:', error);
            return null;
          }
        }
        
        function handleCopyClick(element, textToCopy) {
          navigator.clipboard.writeText(textToCopy).then(function() {
            element.classList.add('copied');
            
            setTimeout(() => {
              element.classList.remove('copied');
            }, 2000);
          }).catch(function(err) {
            console.error('复制失败:', err);
          });
        }
        
        function getRecordClass(recordType) {
          switch(recordType) {
            case 1: return 'record-a';
            case 28: return 'record-aaaa';
            case 5: return 'record-cname';
            case 2: return 'record-ns';
            case 6: return 'record-soa';
            default: return 'record-other';
          }
        }
        
        function getRecordTypeName(recordType) {
          switch(recordType) {
            case 1: return 'A';
            case 28: return 'AAAA';
            case 5: return 'CNAME';
            case 2: return 'NS';
            case 6: return 'SOA';
            default: return '类型 ' + recordType;
          }
        }
        
        function getRecordTypeClass(recordType) {
          switch(recordType) {
            case 1: return 'type-a';
            case 28: return 'type-aaaa';
            case 5: return 'type-cname';
            case 2: return 'type-ns';
            case 6: return 'type-soa';
            default: return 'type-other';
          }
        }
        
        function displayRecords(data) {
          document.getElementById('resultContainer').style.display = 'block';
          document.getElementById('errorContainer').style.display = 'none';
          document.getElementById('result').textContent = JSON.stringify(data, null, 2);
          
          const ipv4Records = data.ipv4?.records || [];
          const ipv4Container = document.getElementById('ipv4Records');
          ipv4Container.innerHTML = '';
          
          if (ipv4Records.length === 0) {
            document.getElementById('ipv4Summary').innerHTML = \`<strong>未找到 IPv4 记录</strong>\`;
          } else {
            document.getElementById('ipv4Summary').innerHTML = \`<strong>找到 \${ipv4Records.length} 条 IPv4 记录</strong>\`;
            
            ipv4Records.forEach(record => {
              const recordClass = getRecordClass(record.type);
              const typeClass = getRecordTypeClass(record.type);
              const recordDiv = document.createElement('div');
              recordDiv.className = \`ip-record \${recordClass}\`;
              
              if (record.type === 5) {
                recordDiv.innerHTML = \`
                  <div class="ip-record-row">
                    <div class="ip-record-cell">域名</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">类型</div>
                    <div class="ip-record-cell">
                      <span class="record-type \${typeClass}">\${getRecordTypeName(record.type)}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">TTL</div>
                    <div class="ip-record-cell">
                      <span class="ttl-info">\${formatTTL(record.TTL)}</span>
                    </div>
                  </div>
                \`;
                ipv4Container.appendChild(recordDiv);
                
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 1) {
                recordDiv.innerHTML = \`
                  <div class="ip-record-row">
                    <div class="ip-record-cell">IP地址</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">地理位置</div>
                    <div class="ip-record-cell">
                      <span class="geo-loading">正在获取位置信息...</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">类型</div>
                    <div class="ip-record-cell">
                      <span class="record-type \${typeClass}">\${getRecordTypeName(record.type)}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">TTL</div>
                    <div class="ip-record-cell">
                      <span class="ttl-info">\${formatTTL(record.TTL)}</span>
                    </div>
                  </div>
                \`;
                ipv4Container.appendChild(recordDiv);
                
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
                const geoInfoSpan = recordDiv.querySelector('.geo-loading');
                
                if (isBlockedIP(record.data)) {
                  queryIpGeoInfo(record.data).then(geoData => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                    
                    if (geoData && geoData.status === 'success' && geoData.as) {
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as;
                      geoInfoSpan.appendChild(document.createTextNode(' '));
                      geoInfoSpan.appendChild(asSpan);
                    }
                  }).catch(() => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                  });
                } else {
                  queryIpGeoInfo(record.data).then(geoData => {
                    if (geoData && geoData.status === 'success') {
                      geoInfoSpan.innerHTML = '';
                      geoInfoSpan.classList.remove('geo-loading');
                      
                      const countrySpan = document.createElement('span');
                      countrySpan.className = 'geo-country';
                      countrySpan.textContent = geoData.country || '未知国家';
                      geoInfoSpan.appendChild(countrySpan);
                      
                      if (geoData.as) {
                        const asSpan = document.createElement('span');
                        asSpan.className = 'geo-as';
                        asSpan.textContent = geoData.as;
                        geoInfoSpan.appendChild(document.createTextNode(' '));
                        geoInfoSpan.appendChild(asSpan);
                      }
                    } else {
                      geoInfoSpan.textContent = '位置信息获取失败';
                    }
                  });
                }
              }
            });
          }
          
          const ipv6Records = data.ipv6?.records || [];
          const ipv6Container = document.getElementById('ipv6Records');
          ipv6Container.innerHTML = '';
          
          if (ipv6Records.length === 0) {
            document.getElementById('ipv6Summary').innerHTML = \`<strong>未找到 IPv6 记录</strong>\`;
          } else {
            document.getElementById('ipv6Summary').innerHTML = \`<strong>找到 \${ipv6Records.length} 条 IPv6 记录</strong>\`;
            
            ipv6Records.forEach(record => {
              const recordClass = getRecordClass(record.type);
              const typeClass = getRecordTypeClass(record.type);
              const recordDiv = document.createElement('div');
              recordDiv.className = \`ip-record \${recordClass}\`;
              
              if (record.type === 5) {
                recordDiv.innerHTML = \`
                  <div class="ip-record-row">
                    <div class="ip-record-cell">域名</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">类型</div>
                    <div class="ip-record-cell">
                      <span class="record-type \${typeClass}">\${getRecordTypeName(record.type)}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">TTL</div>
                    <div class="ip-record-cell">
                      <span class="ttl-info">\${formatTTL(record.TTL)}</span>
                    </div>
                  </div>
                \`;
                ipv6Container.appendChild(recordDiv);
                
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 28) {
                recordDiv.innerHTML = \`
                  <div class="ip-record-row">
                    <div class="ip-record-cell">IP地址</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">地理位置</div>
                    <div class="ip-record-cell">
                      <span class="geo-loading">正在获取位置信息...</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">类型</div>
                    <div class="ip-record-cell">
                      <span class="record-type \${typeClass}">\${getRecordTypeName(record.type)}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">TTL</div>
                    <div class="ip-record-cell">
                      <span class="ttl-info">\${formatTTL(record.TTL)}</span>
                    </div>
                  </div>
                \`;
                ipv6Container.appendChild(recordDiv);
                
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
                const geoInfoSpan = recordDiv.querySelector('.geo-loading');
                
                if (isBlockedIP(record.data)) {
                  queryIpGeoInfo(record.data).then(geoData => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                    
                    if (geoData && geoData.status === 'success' && geoData.as) {
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as;
                      geoInfoSpan.appendChild(document.createTextNode(' '));
                      geoInfoSpan.appendChild(asSpan);
                    }
                  }).catch(() => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                  });
                } else {
                  queryIpGeoInfo(record.data).then(geoData => {
                    if (geoData && geoData.status === 'success') {
                      geoInfoSpan.innerHTML = '';
                      geoInfoSpan.classList.remove('geo-loading');
                      
                      const countrySpan = document.createElement('span');
                      countrySpan.className = 'geo-country';
                      countrySpan.textContent = geoData.country || '未知国家';
                      geoInfoSpan.appendChild(countrySpan);
                      
                      if (geoData.as) {
                        const asSpan = document.createElement('span');
                        asSpan.className = 'geo-as';
                        asSpan.textContent = geoData.as;
                        geoInfoSpan.appendChild(document.createTextNode(' '));
                        geoInfoSpan.appendChild(asSpan);
                      }
                    } else {
                      geoInfoSpan.textContent = '位置信息获取失败';
                    }
                  });
                }
              }
            });
          }
          
          const nsRecords = data.ns?.records || [];
          const nsContainer = document.getElementById('nsRecords');
          nsContainer.innerHTML = '';
          
          if (nsRecords.length === 0) {
            document.getElementById('nsSummary').innerHTML = \`<strong>未找到 NS 记录</strong>\`;
          } else {
            document.getElementById('nsSummary').innerHTML = \`<strong>找到 \${nsRecords.length} 条名称服务器记录</strong>\`;
            
            nsRecords.forEach(record => {
              const recordClass = getRecordClass(record.type);
              const typeClass = getRecordTypeClass(record.type);
              const recordDiv = document.createElement('div');
              recordDiv.className = \`ip-record \${recordClass}\`;
              
              if (record.type === 2) {
                recordDiv.innerHTML = \`
                  <div class="ip-record-row">
                    <div class="ip-record-cell">名称服务器</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">类型</div>
                    <div class="ip-record-cell">
                      <span class="record-type \${typeClass}">\${getRecordTypeName(record.type)}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">TTL</div>
                    <div class="ip-record-cell">
                      <span class="ttl-info">\${formatTTL(record.TTL)}</span>
                    </div>
                  </div>
                \`;
                
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 6) {
                const soaParts = record.data.split(' ');
                let adminEmail = soaParts[1].replace('.', '@');
                if (adminEmail.endsWith('.')) adminEmail = adminEmail.slice(0, -1);
                
                recordDiv.innerHTML = \`
                  <div class="ip-record-row">
                    <div class="ip-record-cell">域名</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${record.name}">\${record.name}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">类型</div>
                    <div class="ip-record-cell">
                      <span class="record-type \${typeClass}">\${getRecordTypeName(record.type)}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">主 NS</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${soaParts[0]}">\${soaParts[0]}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">管理邮箱</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${adminEmail}">\${adminEmail}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">序列号</div>
                    <div class="ip-record-cell">
                      <span>\${soaParts[2]}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">刷新间隔</div>
                    <div class="ip-record-cell">
                      <span>\${formatTTL(soaParts[3])}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">重试间隔</div>
                    <div class="ip-record-cell">
                      <span>\${formatTTL(soaParts[4])}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">过期时间</div>
                    <div class="ip-record-cell">
                      <span>\${formatTTL(soaParts[5])}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">最小 TTL</div>
                    <div class="ip-record-cell">
                      <span>\${formatTTL(soaParts[6])}</span>
                    </div>
                  </div>
                \`;
                
                const copyElems = recordDiv.querySelectorAll('.ip-address');
                copyElems.forEach(elem => {
                  elem.addEventListener('click', function() {
                    handleCopyClick(this, this.getAttribute('data-copy'));
                  });
                });
                
              } else {
                recordDiv.innerHTML = \`
                  <div class="ip-record-row">
                    <div class="ip-record-cell">数据</div>
                    <div class="ip-record-cell">
                      <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">类型</div>
                    <div class="ip-record-cell">
                      <span class="record-type \${typeClass}">\${getRecordTypeName(record.type)}</span>
                    </div>
                  </div>
                  <div class="ip-record-row">
                    <div class="ip-record-cell">TTL</div>
                    <div class="ip-record-cell">
                      <span class="ttl-info">\${formatTTL(record.TTL)}</span>
                    </div>
                  </div>
                \`;
                
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
              }
              
              nsContainer.appendChild(recordDiv);
            });
          }
          
          document.getElementById('copyBtn').style.display = 'block';
        }
        
        function displayError(message) {
          document.getElementById('resultContainer').style.display = 'none';
          document.getElementById('errorContainer').style.display = 'block';
          document.getElementById('errorMessage').textContent = message;
          document.getElementById('copyBtn').style.display = 'none';
        }
        
        document.getElementById('resolveForm').addEventListener('submit', async function(e) {
          e.preventDefault();
          const dohSelect = document.getElementById('dohSelect').value;
          let doh;
          
          if(dohSelect === 'current') {
            doh = currentDohUrl;
          } else if(dohSelect === 'custom') {
            doh = document.getElementById('customDoh').value;
            if (!doh) {
              alert('请输入自定义 DoH 地址');
              return;
            }
          } else {
            doh = dohSelect;
          }
          
          const domain = document.getElementById('domain').value;
          if (!domain) {
            alert('请输入需要解析的域名');
            return;
          }
          
          document.getElementById('loading').style.display = 'block';
          document.getElementById('resultContainer').style.display = 'none';
          document.getElementById('errorContainer').style.display = 'none';
          document.getElementById('copyBtn').style.display = 'none';
          
          try {
            const response = await fetch(\`?doh=\${encodeURIComponent(doh)}&domain=\${encodeURIComponent(domain)}&type=all\`);
            
            if (!response.ok) {
              throw new Error(\`HTTP 错误: \${response.status}\`);
            }
            
            const json = await response.json();
            
            if (json.error) {
              displayError(json.error);
            } else {
              displayRecords(json);
            }
          } catch (error) {
            displayError('查询失败: ' + error.message);
          } finally {
            document.getElementById('loading').style.display = 'none';
          }
        });
        
        document.addEventListener('DOMContentLoaded', function() {
          initTheme();
          
          document.getElementById('themeToggle').addEventListener('click', toggleTheme);
          
          const lastDomain = localStorage.getItem('lastDomain');
          if (lastDomain) {
            document.getElementById('domain').value = lastDomain;
          }
          
          document.getElementById('domain').addEventListener('input', function() {
            localStorage.setItem('lastDomain', this.value);
          });

          document.getElementById('currentDomain').textContent = currentHost;
          
          const currentDohOption = document.getElementById('currentDohOption');
          if (currentDohOption) {
            currentDohOption.textContent = currentDohUrl + ' (当前站点)';
          }
          
          const dohUrlDisplay = document.getElementById('dohUrlDisplay');
          if (dohUrlDisplay) {
            dohUrlDisplay.addEventListener('click', function() {
              const textToCopy = currentProtocol + '//' + currentHost + '/' + currentDohPath;
              navigator.clipboard.writeText(textToCopy).then(function() {
                dohUrlDisplay.classList.add('copied');
                setTimeout(() => {
                  dohUrlDisplay.classList.remove('copied');
                }, 2000);
              }).catch(function(err) {
                console.error('复制失败:', err);
              });
            });
          }

          document.getElementById('getJsonBtn').addEventListener('click', function() {
            const dohSelect = document.getElementById('dohSelect').value;
            let dohUrl;
            
            if(dohSelect === 'current') {
              dohUrl = currentDohUrl;
            } else if(dohSelect === 'custom') {
              dohUrl = document.getElementById('customDoh').value;
              if (!dohUrl) {
                alert('请输入自定义 DoH 地址');
                return;
              }
            } else {
              dohUrl = dohSelect;
            }
            
            const domain = document.getElementById('domain').value;
            if (!domain) {
              alert('请输入需要解析的域名');
              return;
            }
            
            let jsonUrl = new URL(dohUrl);
            jsonUrl.searchParams.set('name', domain);
            
            window.open(jsonUrl.toString(), '_blank');
          });
        });
  </script>
</body>
</html>`;
	return new Response(html, {
		headers: { "content-type": "text/html;charset=UTF-8" },
	});
}
async function 代理URL(代理网址, 目标网址) {
	const 网址列表 = await 整理(代理网址);
	const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];
	const 解析后的网址 = new URL(完整网址);
	console.log(解析后的网址);
	const 协议 = 解析后的网址.protocol.slice(0, -1) || "https";
	const 主机名 = 解析后的网址.hostname;
	let 路径名 = 解析后的网址.pathname;
	const 查询参数 = 解析后的网址.search;
	if (路径名.charAt(路径名.length - 1) == "/") {
		路径名 = 路径名.slice(0, -1);
	}
	路径名 += 目标网址.pathname;
	const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;
	const 响应 = await fetch(新网址);
	let 新响应 = new Response(响应.body, {
		status: 响应.status,
		statusText: 响应.statusText,
		headers: 响应.headers,
	});
	新响应.headers.set("X-New-URL", 新网址);
	return 新响应;
}
async function 整理(内容) {
	var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ",").replace(/,+/g, ",");
	if (替换后的内容.charAt(0) == ",") 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ",")
		替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(",");
	return 地址数组;
}
async function nginx() {
	const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`;
	return text;
}