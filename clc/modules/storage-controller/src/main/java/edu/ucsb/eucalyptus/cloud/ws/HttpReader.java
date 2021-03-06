package edu.ucsb.eucalyptus.cloud.ws;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.zip.GZIPInputStream;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.log4j.Logger;

import com.eucalyptus.util.StorageProperties;

import edu.ucsb.eucalyptus.util.SystemUtil;
import edu.ucsb.eucalyptus.util.WalrusDataMessage;



public class HttpReader extends HttpTransfer {

	private static Logger LOG = Logger.getLogger(HttpReader.class);

	private LinkedBlockingQueue<WalrusDataMessage> getQueue;
	private HttpClient httpClient;
	private HttpMethodBase method;
	private File file;
	private boolean compressed;

	public HttpReader(String path, LinkedBlockingQueue<WalrusDataMessage> getQueue, File file, String eucaOperation, String eucaHeader) {
		this.getQueue = getQueue;
		this.file = file;
		httpClient = new HttpClient();

		String httpVerb = "GET";
		String addr = StorageProperties.WALRUS_URL + "/" + path;

		method = constructHttpMethod(httpVerb, addr, eucaOperation, eucaHeader);
	}

	public HttpReader(String path, LinkedBlockingQueue<WalrusDataMessage> getQueue, File file, String eucaOperation, String eucaHeader, boolean compressed) {
		this(path, getQueue, file, eucaOperation, eucaHeader);
		this.compressed = compressed;
	}

	public String getResponseAsString() {
		try {
			httpClient.executeMethod(method);
			InputStream inputStream;
			if(compressed) {
				inputStream = new GZIPInputStream(method.getResponseBodyAsStream());
			} else {
				inputStream = method.getResponseBodyAsStream();
			}

			String responseString = "";
			byte[] bytes = new byte[StorageProperties.TRANSFER_CHUNK_SIZE];
			int bytesRead;
			while((bytesRead = inputStream.read(bytes)) > 0) {
				responseString += new String(bytes, 0 , bytesRead);
			}
			method.releaseConnection();
			return responseString;
		} catch(Exception ex) {
			LOG.error(ex, ex);
		}
		return null;
	}

	private void getResponseToFile() {
		byte[] bytes = new byte[StorageProperties.TRANSFER_CHUNK_SIZE];
		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedOut = null;
		try {
			File compressedFile = new File(file.getAbsolutePath() + ".gz");				
			assert(method != null);
			httpClient.executeMethod(method);
			InputStream httpIn;
			httpIn = method.getResponseBodyAsStream();
			int bytesRead;
			fileOutputStream = new FileOutputStream(compressedFile);
			bufferedOut = new BufferedOutputStream(fileOutputStream);
			while((bytesRead = httpIn.read(bytes)) > 0) {
				bufferedOut.write(bytes, 0, bytesRead);
			}

			if(compressed) {
				SystemUtil.run(new String[]{"/bin/gunzip", compressedFile.getAbsolutePath()});
			}
			method.releaseConnection();
		} catch (Exception ex) {
			LOG.error(ex, ex);
		} finally {
			if(bufferedOut != null) {
				try {
					bufferedOut.close();
				} catch (IOException e) {
					LOG.error(e);	
				}
			}
			if(fileOutputStream != null) {
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					LOG.error(e);	
				}
			}
		}
	}

	private void getResponseToQueue() {
		byte[] bytes = new byte[StorageProperties.TRANSFER_CHUNK_SIZE];
		try {
			httpClient.executeMethod(method);
			InputStream httpIn = method.getResponseBodyAsStream();
			int bytesRead;
			getQueue.add(WalrusDataMessage.StartOfData(0));
			while((bytesRead = httpIn.read(bytes)) > 0) {
				getQueue.add(WalrusDataMessage.DataMessage(bytes, bytesRead));
			}
			getQueue.add(WalrusDataMessage.EOF());
		} catch (Exception ex) {
			LOG.error(ex, ex);
		} finally {
			method.releaseConnection();
		}
	}

	public void run() {
		if(getQueue != null) {
			getResponseToQueue();
		} else if(file != null) {
			getResponseToFile();
		}
	}
}