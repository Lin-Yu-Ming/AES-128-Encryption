module aes(
    input           clk,
    input           rst,
    input  [127:0]  plaintext,
    input  [127:0]  key,
    input  [7:0]    rom_data,
    output reg[7:0]    rom_addr,
    output reg[127:0]  ciphertext,
    output reg done
);

reg [4:0] state,next_state;
reg [7:0] matrix_tmp1 [0:15];
reg [7:0] matrix_tmp [0:15];
reg [7:0] key_matrix [0:15];

reg [7:0] key_constant[0:3];


reg [7:0] nex_matrix[0:15];
reg [8:0] poly_0[0:15];
reg [8:0] poly_1[0:15];
reg [8:0] poly_2[0:15];
reg [8:0] poly_3[0:15];

reg [7:0] round_constant[9:0];
reg [4:0] n,i,c,j,e,round,k;


parameter INIT=4'd0, ADDITION=4'd1,WAIT=4'd2,RIJNDAEL_ADDR=4'd3,RIJNDAEL_DATA=4'd4,
          SHIFTROWS=4'd5,MIXCOLUMS=4'd6,KEY_EXPANSION_ROT=4'd7,KEY_EXPANSION_SUB_ADDR=4'd8
          ,WAIT1=4'd9,KEY_EXPANSION_SUB_DATA=4'd10,ROUND_KEY=4'd11;

always @(posedge clk or posedge rst) begin
    if(rst) state=INIT;
    else state=next_state;
    
end

always @(*) begin
    case (state)
        INIT:begin
            next_state=ADDITION;
        end 

        ADDITION:begin
            next_state=(done!=1)?RIJNDAEL_ADDR:INIT;
        end

        RIJNDAEL_ADDR:begin
            next_state=WAIT;
        end

        WAIT:begin
            next_state=RIJNDAEL_DATA;
        end

        RIJNDAEL_DATA:begin
           next_state=(i<16)? RIJNDAEL_ADDR:SHIFTROWS;
        end

        SHIFTROWS:begin
            next_state=(round<9)?MIXCOLUMS:KEY_EXPANSION_ROT;
        end

        MIXCOLUMS:begin
            next_state=KEY_EXPANSION_SUB_ADDR;
        end

        KEY_EXPANSION_ROT:begin
            next_state=KEY_EXPANSION_SUB_ADDR;
        end

        KEY_EXPANSION_SUB_ADDR:begin
            next_state=WAIT1;
        end

        WAIT1:begin
            next_state=KEY_EXPANSION_SUB_DATA; 
        end

        KEY_EXPANSION_SUB_DATA:begin
            next_state=(e<4)?KEY_EXPANSION_SUB_ADDR:ROUND_KEY;
        end

        ROUND_KEY:begin
            next_state=ADDITION;
        end
    endcase
end

always @(posedge clk ) begin
    case (state)
        INIT:begin
           n=4'd0;
           i=4'd0;
           j=4'd0; 
           e=4'd0;   
           c=4'd0; 
           k=4'd0;
           done=1'b0;
           round=4'd0;
           round_constant[0]=8'h1;
           round_constant[1]=8'h2;
           round_constant[2]=8'h4;
           round_constant[3]=8'h8;
           round_constant[4]=8'h10;
           round_constant[5]=8'h20;
           round_constant[6]=8'h40;
           round_constant[7]=8'h80;
           round_constant[8]=8'h1b;
           round_constant[9]=8'h36;
        end 

        ADDITION:begin
            if(c==0)begin
                key_matrix[0]=key[127:120];
                key_matrix[1]=key[119:112];
                key_matrix[2]=key[111:104];
                key_matrix[3]=key[103:96];
                key_matrix[4]=key[95:88];
                key_matrix[5]=key[87:80];
                key_matrix[6]=key[79:72];
                key_matrix[7]=key[71:64];
                key_matrix[8]=key[63:56];
                key_matrix[9]=key[55:48];
                key_matrix[10]=key[47:40];
                key_matrix[11]=key[39:32];
                key_matrix[12]=key[31:24];
                key_matrix[13]=key[23:16];
                key_matrix[14]=key[15:8];
                key_matrix[15]=key[7:0];

                matrix_tmp[0]=plaintext[127:120]^key_matrix[0];
                matrix_tmp[1]=plaintext[119:112]^key_matrix[1];
                matrix_tmp[2]=plaintext[111:104]^key_matrix[2];
                matrix_tmp[3]=plaintext[103:96]^key_matrix[3];
                matrix_tmp[4]=plaintext[95:88]^key_matrix[4];
                matrix_tmp[5]=plaintext[87:80]^key_matrix[5];
                matrix_tmp[6]=plaintext[79:72]^key_matrix[6];
                matrix_tmp[7]=plaintext[71:64]^key_matrix[7];
                matrix_tmp[8]=plaintext[63:56]^key_matrix[8];
                matrix_tmp[9]=plaintext[55:48]^key_matrix[9];
                matrix_tmp[10]=plaintext[47:40]^key_matrix[10];
                matrix_tmp[11]=plaintext[39:32]^key_matrix[11];
                matrix_tmp[12]=plaintext[31:24]^key_matrix[12];
                matrix_tmp[13]=plaintext[23:16]^key_matrix[13];
                matrix_tmp[14]=plaintext[15:8]^key_matrix[14];
                matrix_tmp[15]=plaintext[7:0]^key_matrix[15];

                c=c+1;     
            end
            else begin
                if (round<9) begin
                    n=4'd0;
                    i=4'd0;
                    j=4'd0; 
                    e=4'd0;
                    matrix_tmp[0]=nex_matrix[0]^key_matrix[0];
                    matrix_tmp[1]=nex_matrix[4]^key_matrix[1];
                    matrix_tmp[2]=nex_matrix[8]^key_matrix[2];
                    matrix_tmp[3]=nex_matrix[12]^key_matrix[3];
                    matrix_tmp[4]=nex_matrix[1]^key_matrix[4];
                    matrix_tmp[5]=nex_matrix[5]^key_matrix[5];
                    matrix_tmp[6]=nex_matrix[9]^key_matrix[6];
                    matrix_tmp[7]=nex_matrix[13]^key_matrix[7];
                    matrix_tmp[8]=nex_matrix[2]^key_matrix[8];
                    matrix_tmp[9]=nex_matrix[6]^key_matrix[9];
                    matrix_tmp[10]=nex_matrix[10]^key_matrix[10];
                    matrix_tmp[11]=nex_matrix[14]^key_matrix[11];
                    matrix_tmp[12]=nex_matrix[3]^key_matrix[12];
                    matrix_tmp[13]=nex_matrix[7]^key_matrix[13];
                    matrix_tmp[14]=nex_matrix[11]^key_matrix[14];
                    matrix_tmp[15]=nex_matrix[15]^key_matrix[15];
                    round=round+1;    
                end
                else begin
                    matrix_tmp[0]=matrix_tmp1[0]^key_matrix[0];
                    matrix_tmp[1]=matrix_tmp1[1]^key_matrix[1];
                    matrix_tmp[2]=matrix_tmp1[2]^key_matrix[2];
                    matrix_tmp[3]=matrix_tmp1[3]^key_matrix[3];
                    matrix_tmp[4]=matrix_tmp1[4]^key_matrix[4];
                    matrix_tmp[5]=matrix_tmp1[5]^key_matrix[5];
                    matrix_tmp[6]=matrix_tmp1[6]^key_matrix[6];
                    matrix_tmp[7]=matrix_tmp1[7]^key_matrix[7];
                    matrix_tmp[8]=matrix_tmp1[8]^key_matrix[8];
                    matrix_tmp[9]=matrix_tmp1[9]^key_matrix[9];
                    matrix_tmp[10]=matrix_tmp1[10]^key_matrix[10];
                    matrix_tmp[11]=matrix_tmp1[11]^key_matrix[11];
                    matrix_tmp[12]=matrix_tmp1[12]^key_matrix[12];
                    matrix_tmp[13]=matrix_tmp1[13]^key_matrix[13];
                    matrix_tmp[14]=matrix_tmp1[14]^key_matrix[14];
                    matrix_tmp[15]=matrix_tmp1[15]^key_matrix[15];
                    ciphertext={matrix_tmp[0],matrix_tmp[1],matrix_tmp[2],matrix_tmp[3],matrix_tmp[4],matrix_tmp[5],matrix_tmp[6],matrix_tmp[7]
                  ,matrix_tmp[8],matrix_tmp[9],matrix_tmp[10],matrix_tmp[11],matrix_tmp[12],matrix_tmp[13],matrix_tmp[14],matrix_tmp[15]};
                   done=1'b1;
                end   
            end    
        end
        
        RIJNDAEL_ADDR:begin
          rom_addr=matrix_tmp[n];
          n=n+4'd1; 
        end
        
        WAIT:begin       
        end

        RIJNDAEL_DATA:begin
            matrix_tmp[i]=rom_data;
            i=i+1; 
             
        end

        SHIFTROWS:begin             
          matrix_tmp1[0]=matrix_tmp[0];
          matrix_tmp1[1]=matrix_tmp[5];
          matrix_tmp1[2]=matrix_tmp[10];
          matrix_tmp1[3]=matrix_tmp[15];
          matrix_tmp1[4]=matrix_tmp[4];
          matrix_tmp1[5]=matrix_tmp[9];
          matrix_tmp1[6]=matrix_tmp[14];
          matrix_tmp1[7]=matrix_tmp[3];
          matrix_tmp1[8]=matrix_tmp[8];
          matrix_tmp1[9]=matrix_tmp[13];
          matrix_tmp1[10]=matrix_tmp[2];
          matrix_tmp1[11]=matrix_tmp[7];
          matrix_tmp1[12]=matrix_tmp[12];
          matrix_tmp1[13]=matrix_tmp[1];
          matrix_tmp1[14]=matrix_tmp[6];
          matrix_tmp1[15]=matrix_tmp[11];     
        end

        MIXCOLUMS:begin
            poly_0[0]=matrix_tmp1[0]<<1;
            poly_0[1]=(matrix_tmp1[1]<<1)^(matrix_tmp1[1]);
            poly_0[2]=matrix_tmp1[2];
            poly_0[3]=matrix_tmp1[3];
            
            poly_0[4]=matrix_tmp1[4]<<1;
            poly_0[5]=(matrix_tmp1[5]<<1)^(matrix_tmp1[5]);
            poly_0[6]=matrix_tmp1[6];
            poly_0[7]=matrix_tmp1[7];

            poly_0[8]=matrix_tmp1[8]<<1;
            poly_0[9]=(matrix_tmp1[9]<<1)^(matrix_tmp1[9]);
            poly_0[10]=matrix_tmp1[10];
            poly_0[11]=matrix_tmp1[11];

            poly_0[12]=matrix_tmp1[12]<<1;
            poly_0[13]=(matrix_tmp1[13]<<1)^(matrix_tmp1[13]);
            poly_0[14]=matrix_tmp1[14];
            poly_0[15]=matrix_tmp1[15];

            poly_0[0]=(poly_0[0][8])?5'b11011^poly_0[0][7:0]:poly_0[0][7:0];
            poly_0[1]=(poly_0[1][8])?5'b11011^poly_0[1][7:0]:poly_0[1][7:0];
            poly_0[2]=(poly_0[2][8])?5'b11011^poly_0[2][7:0]:poly_0[2][7:0];
            poly_0[3]=(poly_0[3][8])?5'b11011^poly_0[3][7:0]:poly_0[3][7:0];
           
            poly_0[4]=(poly_0[4][8])?5'b11011^poly_0[4][7:0]:poly_0[4][7:0];
            poly_0[5]=(poly_0[5][8])?5'b11011^poly_0[5][7:0]:poly_0[5][7:0];
            poly_0[6]=(poly_0[6][8])?5'b11011^poly_0[6][7:0]:poly_0[6][7:0];
            poly_0[7]=(poly_0[7][8])?5'b11011^poly_0[7][7:0]:poly_0[7][7:0];

            poly_0[8]=(poly_0[8][8])?5'b11011^poly_0[8][7:0]:poly_0[8][7:0];
            poly_0[9]=(poly_0[9][8])?5'b11011^poly_0[9][7:0]:poly_0[9][7:0];
            poly_0[10]=(poly_0[10][8])?5'b11011^poly_0[10][7:0]:poly_0[10][7:0];
            poly_0[11]=(poly_0[11][8])?5'b11011^poly_0[11][7:0]:poly_0[11][7:0];

            poly_0[12]=(poly_0[12][8])?5'b11011^poly_0[12][7:0]:poly_0[12][7:0];
            poly_0[13]=(poly_0[13][8])?5'b11011^poly_0[13][7:0]:poly_0[13][7:0];
            poly_0[14]=(poly_0[14][8])?5'b11011^poly_0[14][7:0]:poly_0[14][7:0];
            poly_0[15]=(poly_0[15][8])?5'b11011^poly_0[15][7:0]:poly_0[15][7:0];
            
            nex_matrix[0]=poly_0[0]^poly_0[1]^poly_0[2]^poly_0[3];
            nex_matrix[1]=poly_0[4]^poly_0[5]^poly_0[6]^poly_0[7];
            nex_matrix[2]=poly_0[8]^poly_0[9]^poly_0[10]^poly_0[11];
            nex_matrix[3]=poly_0[12]^poly_0[13]^poly_0[14]^poly_0[15];

            poly_1[0]=matrix_tmp1[0];
            poly_1[1]=matrix_tmp1[1]<<1;
            poly_1[2]=(matrix_tmp1[2]<<1)^(matrix_tmp1[2]);
            poly_1[3]=matrix_tmp1[3];
            
            poly_1[4]=matrix_tmp1[4];
            poly_1[5]=matrix_tmp1[5]<<1;
            poly_1[6]=(matrix_tmp1[6]<<1)^(matrix_tmp1[6]);
            poly_1[7]=matrix_tmp1[7];

            poly_1[8]=matrix_tmp1[8];
            poly_1[9]=matrix_tmp1[9]<<1;
            poly_1[10]=(matrix_tmp1[10]<<1)^(matrix_tmp1[10]);
            poly_1[11]=matrix_tmp1[11];

            poly_1[12]=matrix_tmp1[12];
            poly_1[13]=matrix_tmp1[13]<<1;
            poly_1[14]=(matrix_tmp1[14]<<1)^(matrix_tmp1[14]);
            poly_1[15]=matrix_tmp1[15];

            poly_1[0]=(poly_1[0][8])?5'b11011^poly_1[0][7:0]:poly_1[0][7:0];
            poly_1[1]=(poly_1[1][8])?5'b11011^poly_1[1][7:0]:poly_1[1][7:0];
            poly_1[2]=(poly_1[2][8])?5'b11011^poly_1[2][7:0]:poly_1[2][7:0];
            poly_1[3]=(poly_1[3][8])?5'b11011^poly_1[3][7:0]:poly_1[3][7:0];
           
            poly_1[4]=(poly_1[4][8])?5'b11011^poly_1[4][7:0]:poly_1[4][7:0];
            poly_1[5]=(poly_1[5][8])?5'b11011^poly_1[5][7:0]:poly_1[5][7:0];
            poly_1[6]=(poly_1[6][8])?5'b11011^poly_1[6][7:0]:poly_1[6][7:0];
            poly_1[7]=(poly_1[7][8])?5'b11011^poly_1[7][7:0]:poly_1[7][7:0];

            poly_1[8]=(poly_1[8][8])?5'b11011^poly_1[8][7:0]:poly_1[8][7:0];
            poly_1[9]=(poly_1[9][8])?5'b11011^poly_1[9][7:0]:poly_1[9][7:0];
            poly_1[10]=(poly_1[10][8])?5'b11011^poly_1[10][7:0]:poly_1[10][7:0];
            poly_1[11]=(poly_1[11][8])?5'b11011^poly_1[11][7:0]:poly_1[11][7:0];

            poly_1[12]=(poly_1[12][8])?5'b11011^poly_1[12][7:0]:poly_1[12][7:0];
            poly_1[13]=(poly_1[13][8])?5'b11011^poly_1[13][7:0]:poly_1[13][7:0];
            poly_1[14]=(poly_1[14][8])?5'b11011^poly_1[14][7:0]:poly_1[14][7:0];
            poly_1[15]=(poly_1[15][8])?5'b11011^poly_1[15][7:0]:poly_1[15][7:0];
 
            nex_matrix[4]=poly_1[0]^poly_1[1]^poly_1[2]^poly_1[3];
            nex_matrix[5]=poly_1[4]^poly_1[5]^poly_1[6]^poly_1[7];
            nex_matrix[6]=poly_1[8]^poly_1[9]^poly_1[10]^poly_1[11];
            nex_matrix[7]=poly_1[12]^poly_1[13]^poly_1[14]^poly_1[15];

            poly_2[0]=matrix_tmp1[0];
            poly_2[1]=matrix_tmp1[1];
            poly_2[2]=matrix_tmp1[2]<<1;
            poly_2[3]=(matrix_tmp1[3]<<1)^(matrix_tmp1[3]);
            
            poly_2[4]=matrix_tmp1[4];
            poly_2[5]=matrix_tmp1[5];
            poly_2[6]=matrix_tmp1[6]<<1;
            poly_2[7]=(matrix_tmp1[7]<<1)^(matrix_tmp1[7]);

            poly_2[8]=matrix_tmp1[8];
            poly_2[9]=matrix_tmp1[9];
            poly_2[10]=matrix_tmp1[10]<<1;
            poly_2[11]=(matrix_tmp1[11]<<1)^(matrix_tmp1[11]);

            poly_2[12]=matrix_tmp1[12];
            poly_2[13]=matrix_tmp1[13];
            poly_2[14]=matrix_tmp1[14]<<1;
            poly_2[15]=(matrix_tmp1[15]<<1)^(matrix_tmp1[15]);

            poly_2[0]=(poly_2[0][8])?5'b11011^poly_2[0][7:0]:poly_2[0][7:0];
            poly_2[1]=(poly_2[1][8])?5'b11011^poly_2[1][7:0]:poly_2[1][7:0];
            poly_2[2]=(poly_2[2][8])?5'b11011^poly_2[2][7:0]:poly_2[2][7:0];
            poly_2[3]=(poly_2[3][8])?5'b11011^poly_2[3][7:0]:poly_2[3][7:0];
           
            poly_2[4]=(poly_2[4][8])?5'b11011^poly_2[4][7:0]:poly_2[4][7:0];
            poly_2[5]=(poly_2[5][8])?5'b11011^poly_2[5][7:0]:poly_2[5][7:0];
            poly_2[6]=(poly_2[6][8])?5'b11011^poly_2[6][7:0]:poly_2[6][7:0];
            poly_2[7]=(poly_2[7][8])?5'b11011^poly_2[7][7:0]:poly_2[7][7:0];

            poly_2[8]=(poly_2[8][8])?5'b11011^poly_2[8][7:0]:poly_2[8][7:0];
            poly_2[9]=(poly_2[9][8])?5'b11011^poly_2[9][7:0]:poly_2[9][7:0];
            poly_2[10]=(poly_2[10][8])?5'b11011^poly_2[10][7:0]:poly_2[10][7:0];
            poly_2[11]=(poly_2[11][8])?5'b11011^poly_2[11][7:0]:poly_2[11][7:0];

            poly_2[12]=(poly_2[12][8])?5'b11011^poly_2[12][7:0]:poly_2[12][7:0];
            poly_2[13]=(poly_2[13][8])?5'b11011^poly_2[13][7:0]:poly_2[13][7:0];
            poly_2[14]=(poly_2[14][8])?5'b11011^poly_2[14][7:0]:poly_2[14][7:0];
            poly_2[15]=(poly_2[15][8])?5'b11011^poly_2[15][7:0]:poly_2[15][7:0];

            nex_matrix[8]=poly_2[0]^poly_2[1]^poly_2[2]^poly_2[3];
            nex_matrix[9]=poly_2[4]^poly_2[5]^poly_2[6]^poly_2[7];
            nex_matrix[10]=poly_2[8]^poly_2[9]^poly_2[10]^poly_2[11];
            nex_matrix[11]=poly_2[12]^poly_2[13]^poly_2[14]^poly_2[15];

            poly_3[0]=(matrix_tmp1[0]<<1)^(matrix_tmp1[0]);
            poly_3[1]=matrix_tmp1[1];
            poly_3[2]=matrix_tmp1[2];
            poly_3[3]=matrix_tmp1[3]<<1;
            
            poly_3[4]=(matrix_tmp1[4]<<1)^(matrix_tmp1[4]);
            poly_3[5]=matrix_tmp1[5];
            poly_3[6]=matrix_tmp1[6];
            poly_3[7]=matrix_tmp1[7]<<1;

            poly_3[8]=(matrix_tmp1[8]<<1)^(matrix_tmp1[8]);
            poly_3[9]=matrix_tmp1[9];
            poly_3[10]=matrix_tmp1[10];
            poly_3[11]=matrix_tmp1[11]<<1;

            poly_3[12]=(matrix_tmp1[12]<<1)^(matrix_tmp1[12]);
            poly_3[13]=matrix_tmp1[13];
            poly_3[14]=matrix_tmp1[14];
            poly_3[15]=matrix_tmp1[15]<<1;

            poly_3[0]=(poly_3[0][8])?5'b11011^poly_3[0][7:0]:poly_3[0][7:0];
            poly_3[1]=(poly_3[1][8])?5'b11011^poly_3[1][7:0]:poly_3[1][7:0];
            poly_3[2]=(poly_3[2][8])?5'b11011^poly_3[2][7:0]:poly_3[2][7:0];
            poly_3[3]=(poly_3[3][8])?5'b11011^poly_3[3][7:0]:poly_3[3][7:0];
           
            poly_3[4]=(poly_3[4][8])?5'b11011^poly_3[4][7:0]:poly_3[4][7:0];
            poly_3[5]=(poly_3[5][8])?5'b11011^poly_3[5][7:0]:poly_3[5][7:0];
            poly_3[6]=(poly_3[6][8])?5'b11011^poly_3[6][7:0]:poly_3[6][7:0];
            poly_3[7]=(poly_3[7][8])?5'b11011^poly_3[7][7:0]:poly_3[7][7:0];

            poly_3[8]=(poly_3[8][8])?5'b11011^poly_3[8][7:0]:poly_3[8][7:0];
            poly_3[9]=(poly_3[9][8])?5'b11011^poly_3[9][7:0]:poly_3[9][7:0];
            poly_3[10]=(poly_3[10][8])?5'b11011^poly_3[10][7:0]:poly_3[10][7:0];
            poly_3[11]=(poly_3[11][8])?5'b11011^poly_3[11][7:0]:poly_3[11][7:0];

            poly_3[12]=(poly_3[12][8])?5'b11011^poly_3[12][7:0]:poly_3[12][7:0];
            poly_3[13]=(poly_3[13][8])?5'b11011^poly_3[13][7:0]:poly_3[13][7:0];
            poly_3[14]=(poly_3[14][8])?5'b11011^poly_3[14][7:0]:poly_3[14][7:0];
            poly_3[15]=(poly_3[15][8])?5'b11011^poly_3[15][7:0]:poly_3[15][7:0];

            nex_matrix[12]=poly_3[0]^poly_3[1]^poly_3[2]^poly_3[3];
            nex_matrix[13]=poly_3[4]^poly_3[5]^poly_3[6]^poly_3[7];
            nex_matrix[14]=poly_3[8]^poly_3[9]^poly_3[10]^poly_3[11];
            nex_matrix[15]=poly_3[12]^poly_3[13]^poly_3[14]^poly_3[15];

            key_constant[0]=key_matrix[13];
            key_constant[1]=key_matrix[14];
            key_constant[2]=key_matrix[15];
            key_constant[3]=key_matrix[12];
        end  


        KEY_EXPANSION_ROT:begin
            key_constant[0]=key_matrix[13];
            key_constant[1]=key_matrix[14];
            key_constant[2]=key_matrix[15];
            key_constant[3]=key_matrix[12];
        end

        KEY_EXPANSION_SUB_ADDR:begin
            rom_addr=key_constant[j];
            j=j+4'd1;
        end

        WAIT1:begin
          
        end
 
        KEY_EXPANSION_SUB_DATA:begin
            key_constant[e]=rom_data;
            e=e+1;
        end

        ROUND_KEY:begin
           key_constant[0]=key_constant[0]^round_constant[k];
           key_constant[1]=key_constant[1];
           key_constant[2]=key_constant[2];
           key_constant[3]=key_constant[3];

           key_matrix[0]=key_matrix[0]^key_constant[0];
           key_matrix[1]=key_matrix[1]^key_constant[1];
           key_matrix[2]=key_matrix[2]^key_constant[2];
           key_matrix[3]=key_matrix[3]^key_constant[3];

           key_matrix[4]=key_matrix[0]^key_matrix[4];
           key_matrix[5]=key_matrix[1]^key_matrix[5];
           key_matrix[6]=key_matrix[2]^key_matrix[6];
           key_matrix[7]=key_matrix[3]^key_matrix[7];

           key_matrix[8]=key_matrix[4]^key_matrix[8];
           key_matrix[9]=key_matrix[5]^key_matrix[9];
           key_matrix[10]=key_matrix[6]^key_matrix[10];
           key_matrix[11]=key_matrix[7]^key_matrix[11];

           key_matrix[12]=key_matrix[8]^key_matrix[12];
           key_matrix[13]=key_matrix[9]^key_matrix[13];
           key_matrix[14]=key_matrix[10]^key_matrix[14];
           key_matrix[15]=key_matrix[11]^key_matrix[15];

           k=k+1;
        end

        default:begin
        end

    endcase   
end

endmodule
