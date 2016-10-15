#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <poll.h>
#include <linux/usb/gadgetfs.h>
#include <sys/types.h>
#include <iostream>
#include <math.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <cstring>
#include <sys/mount.h>
#include "signal.h"

int gadgetFile, outEp, inEp;

int fatFile;

static pthread_t gadgetThread, outThread, inThread;

// max lun at ff breaks ps3 - buffer issue
// mess with all command buffers
// mess with device and block size
// ignoring lots of 5a and 1a commands turns ps3 off

#define FILE_SIZE 0x1000000
#define FILE_BLOCK_SIZE 512

unsigned char fileBuff[FILE_SIZE];

unsigned char dumpedDescriptor[] = {
	0x00, 0x00, 0x00, 0x00,
	0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x64,
	0x09, 0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00,
	0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00,
	0x07, 0x05, 0x02, 0x02, 0x00, 0x02, 0x00,
	0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x64,
	0x09, 0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00,
	0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00,
	0x07, 0x05, 0x02, 0x02, 0x00, 0x02, 0x00,
	0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0xfe, 0x13, 0x23, 0x1e, 0x10, 0x01, 0x01, 0x02, 0x03, 0x01 
};

unsigned char outEpDesc[] = {0x01,0x00,0x00,0x00,0x07, 0x05, 0x02, 0x02, 0x00, 0x02, 0x00,0x07, 0x05, 0x02, 0x02, 0x00, 0x02, 0x00};
unsigned char inEpDesc[] = {0x01,0x00,0x00,0x00,0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00,0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00};

uint8_t borrowedSenseData[] = {
  0x70,			  /* Response Code: fixed, current */
  0x00,
  0x02,			  /* Sense Key */
  0x00, 0x00, 0x00, 0x00,
  0x0a,			  /* Additional Sense Length */
  0x00, 0x00, 0x00, 0x00,
  0x3a,			  /* ASC (additional sense code) */
  0x00,			  /* ASCQ (additional sense code qualifier) */
  0x00,
  0x00, 0x00, 0x00,
};

static const uint8_t scsi_inquiry_data_00[] = { 0, 0, 0, 0, 0 };

static const uint8_t scsi_inquiry_data_83[] = {
  0x00,
  0x83,   /* page code 0x83 */
  0x00,   /* page length MSB */
  0x00    /* page length LSB */
};

static const uint8_t scsi_inquiry_data[] = {
  0x00,				/* Direct Access Device.      */
  0x80,				/* RMB = 1: Removable Medium. */
  0x00,				/* Version: does not claim conformance.  */
  0x02,				/* Response format: SPC-3.    */
  36 - 4,			/* Additional Length.         */
  0x00,
  0x00,
  0x00,
				/* Vendor Identification */
  'F', 'S', 'I', 'J', ' ', ' ', ' ', ' ',
				/* Product Identification */
  'F', 'r', 'a', 'u', 'c', 'h', 'e', 'k',
  'y', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
				/* Product Revision Level */
  '1', '.', '0', ' '
};

// Offset (Hex)	Type	Description
// 0x00	int32	Signature (0x43425355)
// 0x04	int32	Tag (Transaction Unique Identifier)
// 0x08	int32	Length
// 0x0c	byte	Direction (0x00 = ToDevice, 0x80 = ToHost)
// 0x0d	byte	Logical Unit Number
// 0x0e	byte	Command Length
// 0x0f	byte[16]	Command Data

#define CBW_SIGNATURE 0x43425355
#define CSW_SIGNATURE 0x53425355

struct Cbw {
	uint32_t sig;
	uint32_t tag;
	uint32_t length;
	uint8_t direction;
	uint8_t lun;
	uint8_t cmdlen;
	uint8_t cmd[16];
} __attribute__((packed));;

// 0x00	int32	Signature (0x53425355)
// 0x04	int32	Tag (Copied From CBW)
// 0x08	int32	Residue (Difference Between CBW Length And Actual Length)
// 0x0c	byte	Status (0x00 = Success, 0x01 = Failed, 0x02 = Phase Error)

struct Csw {
	uint32_t sig;
	uint32_t tag;
	uint32_t residue;
	uint8_t status;
} __attribute__((packed));;

#define TEST_UNIT 0x00
#define REQUEST_SENSE 0x03 
#define INQUIRY 0x12
#define READ_CAPACITY 0x25
#define MODE_SENSE 0x1a
#define BLOCK_READ 0x28
#define BLOCK_WRITE 0x2a
#define UNKNOWN_COMMAND 0x5a

uint32_t changeEndianness32(uint32_t num) {

	return ((num>>24)&0xff) |
		((num<<8)&0xff0000) |
		((num>>8)&0xff00) |
		((num<<24)&0xff000000);
}

static void* outCheck(void* nothing) {

	struct Cbw cbw;
	struct Csw csw;

	while(1) {

		unsigned char outBuff[512];

		int readVal = read(outEp,(unsigned char*)&cbw,sizeof(struct Cbw));

		printf("sig %08x tag: %08x dir: %02x length %d cmdlen: %d command: ",cbw.sig,cbw.tag,cbw.direction,cbw.length,cbw.cmdlen);
		for(int i = 0 ; i < cbw.cmdlen ; i++) {
			printf("%02x ",cbw.cmd[i]);
		}
		printf("\n");

		if(cbw.sig == CBW_SIGNATURE) {

			csw.sig = CSW_SIGNATURE;
			csw.tag = cbw.tag;
			csw.status = 0;
			csw.residue = cbw.length;

			unsigned char* cbwBuff = (unsigned char*)malloc(cbw.length);

			switch(cbw.cmd[0]) {

				case REQUEST_SENSE: {

					uint8_t allocationLength = cbw.cmd[4];

					write(inEp,borrowedSenseData,cbw.length);

					break;
				}
				case TEST_UNIT:
					
					break;
				case INQUIRY:

					if(cbw.cmd[1]&0x01) {

						if(cbw.cmd[2] == 0x83) {
							write(inEp,scsi_inquiry_data_83,sizeof(scsi_inquiry_data_83));
						} else {
							write(inEp,scsi_inquiry_data_00,sizeof(scsi_inquiry_data_00));
						}

					} else {

						write(inEp,scsi_inquiry_data,sizeof(scsi_inquiry_data));
					}

					break;
				case READ_CAPACITY: {

					printf("Capcities: %08x %d = %08x\n",FILE_SIZE,FILE_BLOCK_SIZE,FILE_SIZE/FILE_BLOCK_SIZE);
					uint32_t numberOfBlocks = changeEndianness32(FILE_SIZE/FILE_BLOCK_SIZE);
					uint32_t blockSize = changeEndianness32(FILE_BLOCK_SIZE);
					memcpy(cbwBuff,(unsigned char*)&numberOfBlocks,4);
					memcpy(&cbwBuff[4],(unsigned char*)&blockSize,4);

				    // cbwBuff[0]  = (uint8_t)((numberOfBlocks - 1) >> 24);
				    // cbwBuff[1]  = (uint8_t)((numberOfBlocks - 1) >> 16);
				    // cbwBuff[2]  = (uint8_t)((numberOfBlocks - 1) >> 8);
				    // cbwBuff[3]  = (uint8_t)((numberOfBlocks - 1) >> 0);
				    // cbwBuff[4]  = (uint8_t)(blockSize >> 24);
				    // cbwBuff[5]  = (uint8_t)(blockSize >> 16);
				    // cbwBuff[6] = (uint8_t)(blockSize >> 8);
				    // cbwBuff[7] = (uint8_t)(blockSize >> 0);

					write(inEp,cbwBuff,8);
					break;
				}
				case MODE_SENSE:

					memset(cbwBuff,0x00,cbw.length);
					cbwBuff[0] = 0x03;
					write(inEp,cbwBuff,cbw.length);

					break;
				case BLOCK_READ: {

					uint32_t offsetPointer = 0;
					memcpy(&offsetPointer,(unsigned char*)&cbw.cmd[2],4);
					offsetPointer = changeEndianness32(offsetPointer);

					memset(cbwBuff,0xff,cbw.length);

					lseek(fatFile,offsetPointer * FILE_BLOCK_SIZE,SEEK_SET);

					// for(int i = 0 ; i < (cbw.length/FILE_BLOCK_SIZE) ; i++) {

					int fatFileReadRet = read(fatFile,cbwBuff,FILE_BLOCK_SIZE);
					printf("Reading offset: %08x ret: %d\n",offsetPointer,fatFileReadRet);
					write(inEp,cbwBuff,FILE_BLOCK_SIZE);
					printf("After file write\n");
					csw.residue = FILE_BLOCK_SIZE;
					// }

					break;
				}
				case BLOCK_WRITE: {

					uint32_t offsetPointer = 0;
					memcpy(&offsetPointer,(unsigned char*)&cbw.cmd[2],4);
					offsetPointer = changeEndianness32(offsetPointer);

					memset(cbwBuff,0xff,cbw.length);

					lseek(fatFile,offsetPointer * FILE_BLOCK_SIZE,SEEK_SET);

					// for(int i = 0 ; i < (cbw.length/FILE_BLOCK_SIZE) ; i++) {
					read(outEp,cbwBuff,FILE_BLOCK_SIZE);

					int fatFileReadRet = write(fatFile,cbwBuff,FILE_BLOCK_SIZE);
					printf("write offset: %08x ret: %d\n",offsetPointer,fatFileReadRet);
					csw.residue = FILE_BLOCK_SIZE;
					// }

					break;
				}
				// case UNKNOWN_COMMAND:

				// 	break;
				default:
					printf("Unknown cbw command: %02x\n",cbw.cmd[0]);
					csw.status = 1;
					csw.residue = 0;
					break;
			}

			write(inEp,(unsigned char*)&csw,sizeof(struct Csw));

			free(cbwBuff);

		}


	}

}

static void handleSetup(struct usb_ctrlrequest *setup) {
	
	uint16_t value = __le16_to_cpu(setup->wValue);
	uint16_t index = __le16_to_cpu(setup->wIndex);
	uint16_t length = __le16_to_cpu(setup->wLength);

	//printf("Got USB bRequest: %d(%02x) with type %d(%02x dir:(%02x)) value: %04x of length %d\n",setup->bRequest,setup->bRequest,setup->bRequestType, setup->bRequestType, setup->bRequestType&0x80, value, setup->wLength);

	// start transactions

	unsigned char* buf = (unsigned char*)malloc(length);

	switch(setup->bRequest) {

		case USB_REQ_SET_CONFIGURATION:
			//printf("set Configuration value %d\n",value);
			read(gadgetFile, NULL, 0);
			break;
		case USB_REQ_SET_INTERFACE:
			//printf("set Interface value %d\n",value);
			read(gadgetFile, NULL, 0);
			break;

		case 0xfe: {// max lun
			buf[0] = 0x0; // random value that may not help things

			int ret = write(gadgetFile, buf, 1);

			//printf("Got new buff: %02x length: %d ret: %d\n",buf[0],length,ret);

			break;
		}
		case 0xff: // reset

			read(gadgetFile, buf, length);

			//printf("Got ff buff\n");

			break;

	}	

	free(buf);

}

static void* inCheck(void* nothing) {

	struct pollfd pollRecv;
    pollRecv.fd=inEp;
    pollRecv.events=POLLIN | POLLOUT | POLLHUP;;

	unsigned char inBuff[512];

	while(1) {

		int pollVal = poll(&pollRecv,1,500);

		if(pollVal >= 0) {

//			printf("Got in poll!\n");
			int writeVal = write(inEp,inBuff,512);

			// printf("Poll write val: %d\n",writeVal);

		}

	}

}


static void* gadgetCfgCb(void* nothing) {

	struct usb_gadgetfs_event events[5];

	struct pollfd pollRecv;
    pollRecv.fd=gadgetFile;
    pollRecv.events=POLLIN | POLLOUT | POLLHUP;;

    printf("Starting gadget read\n");

	char recvData[32];
	int readData;
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	while(true) {
		
		int pollVal = poll(&pollRecv,1,500);

		if(pollVal >= 0) {
		// if(pollVal >= 0 && (pollRecv.revents&POLLIN)) {

			int ret = read(gadgetFile,&events,sizeof(events));

			unsigned char* eventData = (unsigned char*)malloc(sizeof(events[0]));
			
			for(int i = 0 ; i < (ret / sizeof(events[0])) ; i++) {

				switch(events[i].type) {

					case GADGETFS_SETUP:

						handleSetup(&events[i].u.setup);

						break;
					case GADGETFS_NOP:
						break;
					case GADGETFS_CONNECT:
						printf("Connect\n");
						break;
					case GADGETFS_DISCONNECT:
						printf("Disconnect\n");
						break;
					case GADGETFS_SUSPEND:
						printf("Suspend\n");
						break;
					default:
						printf("Unknown type: %d\n",events[i].type);
						exit(0);
						break;
				}

			}
		}

	}
}

int main() {

	mkdir("/dev/gadget/",455);
	umount2("/dev/gadget/", MNT_FORCE);
	int mountRet = mount("none", "/dev/gadget/", "gadgetfs", 0, "");

	if(mountRet < 0) {
		printf("Mounting gadget failed\n");
		return 1;
	}

	fatFile = open("file.img",O_RDWR);

	gadgetFile = open("/dev/gadget/musb-hdrc", O_RDWR);

	if(gadgetFile < 0) {
		printf("Could not open gadget file, got response %d\n", gadgetFile);
		return 1;
	}

	int writeValGadget = write(gadgetFile,dumpedDescriptor,sizeof(dumpedDescriptor)); // make sure length is right
	
	pthread_create(&gadgetThread,0,gadgetCfgCb,NULL);

	outEp = -1;
	
	while(outEp < 0) {
		outEp = open("/dev/gadget/ep2out", O_CLOEXEC | O_RDWR);
	}

	inEp = open("/dev/gadget/ep1in", O_CLOEXEC | O_RDWR);

	int outWritten = -1;

	while(outWritten < 0) {
		outWritten = write(outEp,outEpDesc,sizeof(outEpDesc));
	}

	int inWritten = write(inEp,inEpDesc,sizeof(inEpDesc));

	if(outWritten < 0 || inWritten < 0) {
		printf("Writing endpoint descriptors didn't work\n");
		return 1;
	}

	pthread_create(&outThread,0,outCheck,NULL);
	// pthread_create(&inThread,0,inCheck,NULL);

	while(1);

}