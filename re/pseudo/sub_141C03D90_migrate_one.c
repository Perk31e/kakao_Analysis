c03d90 char __fastcall sub_141C03D90(__int64 a1, int a2, __int64 a3)
       {
       
c03dd7   v5 = sub_1420E59E0(a3, aMain_1);
c03dda   *((_QWORD *)&v55 + 1) = 0;
c03de2   v56 = 0;
c03df9   *(_QWORD *)&v56 = sub_14057FC50(48);
c03e04   v57 = 32;
c03e08   v58 = 47;
c03e17   strcpy((char *)v56, "ATTACH DATABASE ? AS newDb KEY ?");
c03e29   v50[0] = 0;
c03e2e   v6 = &v56;
c03e38   if ( v58 > 0xF )
c03e38     LODWORD(v6) = v56;
c03e54   v7 = sub_1420E1350(a2, (_DWORD)v6, v57, (unsigned int)v50, 0);
c03e56   v8 = v50[0];
c03e5b   *((_QWORD *)&v55 + 1) = v50[0];
c03e68   if ( v58 > 0xF )
         {
c03e6d     v9 = (void *)v56;
c03e79     if ( v58 + 1 >= 0x1000 )
           {
c03e8a       if ( (unsigned __int64)(v56 - *(_QWORD *)(v56 - 8) - 8) > 0x1F )
c03e8a         goto LABEL_54;
c03e94       v9 = *(void **)(v56 - 8);
           }
c03e97     sub_14057EC00(v9);
         }
c03ea7   if ( v7 && v7 != 101 )
         {
c03eb4     v10 = sub_1420E10A0(v7);
c03eb7     v11 = &v70;
c03ebb     v12 = 1;
c03ecb     do
           {
c03ec0       *v11++ = 0;
c03ec7       --v12;
           }
c03ecb     while ( v12 );
c03ecd     v71 = v5;
c03edb     v70 = 0xB000000000000000uLL;
c03ee2     v59 = 0;
c03ee6     v60 = 0;
c03eea     v61 = 15;
c03ef2     LOBYTE(v59) = 0;
c03efa     LODWORD(v50[0]) = 8;
c03f2d     sub_14056FC30(&v59, 69);
c03f32     v51 = 1;
c03f3f     v52 = (__int64)&v70;
c03f4b     *(_QWORD *)&v56 = aFailedToPrepar;
c03f50     *((_QWORD *)&v56 + 1) = 37;
c03f71     sub_14057B2C0((unsigned int)&v53, (unsigned int)&v59, (unsigned int)&v56, (unsigned int)&v51, 0);
c03f77     v13 = &v59;
c03f80     if ( v61 > 0xF )
c03f80       v13 = (__int128 *)v59;
c03f89     v67 = v13;
c03f8d     v68 = v60;
c03f9b     v65 = 0xC000000000000000uLL;
c03f9f     v69 = v10;
c03fad     v66 = 0xB000000000000010uLL;
c03fb4     v62 = 0;
c03fb8     v63 = 0;
c03fbc     v64 = 15;
c03fc4     LOBYTE(v62) = 0;
c03fc8     LODWORD(v50[0]) = 36;
c03fd0     v14 = 0;
c03fd3     for ( i = 0; i < 2; ++i )
           {
c03fe8       v16 = *(&v65 + i) >> 60;
c03fee       if ( (_BYTE)v16 == 12 )
             {
c03ff3         v14 += *(unsigned __int64 *)((char *)&v68 + (*(&v65 + i) & 0xFFFFFFFFFFFFFFFLL));
             }
c03ffc       else if ( (_BYTE)v16 == 11 )
             {
c03ffe         v14 += 32;
             }
             else
             {
c04004         v14 += 8;
             }
           }
c04019     sub_14056FC30(&v62, v14 + 6);
c0401e     *(_QWORD *)&v56 = 2;
c0402b     *((_QWORD *)&v56 + 1) = &v65;
c04037     v51 = (__int64)asc_1429D9FA0;
c0403c     v52 = 6;
c0405d     sub_14057B2C0((unsigned int)&v53, (unsigned int)&v62, (unsigned int)&v51, (unsigned int)&v56, 0);
c0406a     sub_141C05C30(a1, &v62);
c04078     if ( v64 > 0xF )
           {
c0407d       v17 = (void *)v62;
c04088       if ( v64 + 1 >= 0x1000 )
             {
c04099         if ( (unsigned __int64)(v62 - *(_QWORD *)(v62 - 8) - 8) > 0x1F )
c04100           __fastfail(5u);
c0409f         v17 = *(void **)(v62 - 8);
             }
c040a2       sub_14057EC00(v17);
           }
c040a7     v63 = 0;
c040ab     v64 = 15;
c040b3     LOBYTE(v62) = 0;
c040b7     v18 = v61;
c040bf     if ( v61 <= 0xF )
c040bf       goto LABEL_89;
c040c5     v19 = (void *)v59;
c040c5     goto LABEL_28;
         }
c0411c   v20 = sub_1420E19E0(v8, 1, v5, -1, -1);
c0412c   if ( v20 && v20 != 101 )
         {
c04139     v21 = sub_1420E10A0(v20);
c0413c     v22 = &v70;
c04140     v23 = 1;
c0415b     do
           {
c04150       *v22++ = 0;
c04157       --v23;
           }
c0415b     while ( v23 );
c0415d     v71 = v5;
c0416b     v70 = 0xB000000000000000uLL;
c04172     v62 = 0;
c04176     v63 = 0;
c0417a     v64 = 15;
c04182     LOBYTE(v62) = 0;
c04185     LODWORD(v50[0]) = 128;
c041c1     sub_14056FC30(&v62, 67);
c041c6     *(_QWORD *)&v56 = 1;
c041d3     *((_QWORD *)&v56 + 1) = &v70;
c041df     v51 = (__int64)aFailedToBindNe;
c041e4     v52 = 35;
c04205     sub_14057B2C0((unsigned int)&v53, (unsigned int)&v62, (unsigned int)&v51, (unsigned int)&v56, 0);
c0420b     v24 = &v62;
c04214     if ( v64 > 0xF )
c04214       v24 = (__int128 *)v62;
c0421d     v67 = v24;
c04221     v68 = v63;
c0422f     v65 = 0xC000000000000000uLL;
c04233     v69 = v21;
c04241     v66 = 0xB000000000000010uLL;
c04248     v59 = 0;
c0424c     v60 = 0;
c04250     v61 = 15;
c04258     LOBYTE(v59) = 0;
c0425c     LODWORD(v50[0]) = 576;
c04264     v25 = 0;
c04267     for ( j = 0; j < 2; ++j )
           {
c04278       v27 = *(&v65 + j) >> 60;
c0427e       if ( (_BYTE)v27 == 12 )
             {
c04283         v25 += *(unsigned __int64 *)((char *)&v68 + (*(&v65 + j) & 0xFFFFFFFFFFFFFFFLL));
             }
c0428c       else if ( (_BYTE)v27 == 11 )
             {
c0428e         v25 += 32;
             }
             else
             {
c04294         v25 += 8;
             }
           }
c042a9     sub_14056FC30(&v59, v25 + 6);
c042ae     *(_QWORD *)&v56 = 2;
c042bb     *((_QWORD *)&v56 + 1) = &v65;
c042c7     v51 = (__int64)asc_1429D9FA0;
c042cc     v52 = 6;
c042ed     sub_14057B2C0((unsigned int)&v53, (unsigned int)&v59, (unsigned int)&v51, (unsigned int)&v56, 0);
c042fa     sub_141C05C30(a1, &v59);
c04308     if ( v61 > 0xF )
           {
c0430d       v28 = (void *)v59;
c04318       if ( v61 + 1 >= 0x1000 )
             {
c04329         if ( (unsigned __int64)(v59 - *(_QWORD *)(v59 - 8) - 8) > 0x1F )
c04363           __fastfail(5u);
c0432f         v28 = *(void **)(v59 - 8);
             }
c04332       sub_14057EC00(v28);
           }
c04337     v60 = 0;
c0433b     v61 = 15;
c04343     LOBYTE(v59) = 0;
c04347     v18 = v64;
c0434f     if ( v64 <= 0xF )
c0434f       goto LABEL_89;
c04355     v19 = (void *)v62;
       LABEL_28:
c040d3     if ( v18 + 1 < 0x1000 )
           {
       LABEL_31:
c040f1       sub_14057EC00(v19);
       LABEL_89:
c04708       if ( v8 )
c0470d         sub_1420E36F0(v8);
c04714       return 0;
           }
c040e4     if ( (unsigned __int64)v19 - *((_QWORD *)v19 - 1) - 8 <= 0x1F )
           {
c040ea       v19 = (void *)*((_QWORD *)v19 - 1);
c040ea       goto LABEL_31;
           }
       LABEL_54:
c04365     __fastfail(5u);
         }
c0436f   v29 = sub_142400B10(v5);
c04374   *(_QWORD *)&v56 = v5;
c04379   *((_QWORD *)&v56 + 1) = v29;
c0438c   sub_1405C1A40(&v59, 65001, &v56);
c043a1   sub_141CCAC20(a1 + 352, &v65, &v59);
c043ab   sub_14057F790(&v59);
c043b0   v30 = &v65;
c043b9   if ( v68 > 0xF )
c043b9     LODWORD(v30) = v65;
c043d5   v31 = sub_1420E19E0(v8, 2, (_DWORD)v30, -1, -1);
c043e5   if ( v31 && v31 != 101 )
         {
c043f2     v32 = sub_1420E10A0(v31);
c043f5     v33 = &v70;
c043f9     v34 = 1;
c0440b     do
           {
c04400       *v33++ = 0;
c04407       --v34;
           }
c0440b     while ( v34 );
c0440d     v71 = v5;
c0441b     v70 = 0xB000000000000000uLL;
c04422     v59 = 0;
c04426     v60 = 0;
c0442a     v61 = 15;
c04432     LOBYTE(v59) = 0;
c04435     LODWORD(v50[0]) = 2051;
c04471     sub_14056FC30(&v59, 66);
c04476     *(_QWORD *)&v56 = 1;
c04483     *((_QWORD *)&v56 + 1) = &v70;
c0448f     v51 = (__int64)aFailedToBindNe_0;
c04494     v52 = 34;
c044b5     sub_14057B2C0((unsigned int)&v53, (unsigned int)&v59, (unsigned int)&v51, (unsigned int)&v56, 0);
c044bb     v35 = &v59;
c044c4     if ( v61 > 0xF )
c044c4       v35 = (__int128 *)v59;
c044cd     v72 = v35;
c044d1     v73 = v60;
c044df     v70 = 0xC000000000000000uLL;
c044e3     v74 = v32;
c044f1     v71 = 0xB000000000000010uLL;
c044fc     *(_QWORD *)&v56 = asc_1429D9FA0;
c04501     *((_QWORD *)&v56 + 1) = 6;
c0450a     v51 = 2;
c04517     v52 = (__int64)&v70;
c04535     sub_14057BE00(&v62, &v56, &v51);
c04542     sub_141C05C30(a1, &v62);
c04550     if ( v64 > 0xF )
           {
c04555       v36 = (void *)v62;
c04560       if ( v64 + 1 >= 0x1000 )
             {
c04571         if ( (unsigned __int64)(v62 - *(_QWORD *)(v62 - 8) - 8) > 0x1F )
c045f6           __fastfail(5u);
c04577         v36 = *(void **)(v62 - 8);
             }
c0457a       sub_14057EC00(v36);
           }
c0457f     v63 = 0;
c04583     v64 = 15;
c0458b     LOBYTE(v62) = 0;
c04597     if ( v61 > 0xF )
           {
c0459c       v37 = (void *)v59;
c045a7       if ( v61 + 1 >= 0x1000 )
             {
c045b8         if ( (unsigned __int64)(v59 - *(_QWORD *)(v59 - 8) - 8) > 0x1F )
c045fd           __fastfail(5u);
c045be         v37 = *(void **)(v59 - 8);
             }
c045c1       sub_14057EC00(v37);
           }
c045cb     if ( !(_BYTE)v69 )
c045cb       goto LABEL_89;
c045d1     v38 = &v65;
c045da     if ( v68 > 0xF )
c045da       v38 = (unsigned __int64 *)v65;
c045e3     sub_140310200(v38, v67);
c045e8     v39 = &v65;
c045ec     goto LABEL_88;
         }
c04603   if ( (_BYTE)v69 )
         {
c04605     v40 = &v65;
c0460e     if ( v68 > 0xF )
c0460e       v40 = (unsigned __int64 *)v65;
c04617     sub_140310200(v40, v67);
c04620     sub_14057FA60(&v65);
         }
c04628   v41 = sub_1420E2AC0(v8);
c04638   if ( v41 && v41 != 101 )
         {
c04645     v50[0] = sub_1420E10A0(v41);
c0464a     v42 = &v70;
c0464e     v43 = 1;
c0465e     do
           {
c04653       *v42++ = 0;
c0465a       --v43;
           }
c0465e     while ( v43 );
c04660     v71 = v5;
c0466e     v70 = 0xB000000000000000uLL;
c04679     *(_QWORD *)&v56 = aFailedToExecut;
c0467e     *((_QWORD *)&v56 + 1) = 37;
c04687     v51 = 1;
c04694     v52 = (__int64)&v70;
c046b2     sub_14057BE00(&v59, &v56, &v51);
c046bf     *(_QWORD *)&v56 = asc_1429D9FA0;
c046c4     *((_QWORD *)&v56 + 1) = 6;
c046df     v44 = sub_140696240(&v62, &v56, &v59, v50);
c046eb     sub_141C05C30(a1, v44);
c046f5     sub_14057FA60(&v62);
c046fb     v39 = (unsigned __int64 *)&v59;
       LABEL_88:
c046ff     sub_14057FA60(v39);
c046ff     goto LABEL_89;
         }
c0471c   if ( v8 )
c04721     sub_1420E36F0(v8);
c04726   v54 = 0;
c04745   v46 = sub_1420FF040(a2, (unsigned int)aSelectSqlciphe, 0, 0, (__int64)&v54);
c04755   if ( !v46 || v46 == 101 )
         {
c04843     v48 = sub_1420FF040(a2, (unsigned int)aDetachDatabase_0, 0, 0, (__int64)&v54);
c04853     if ( !v48 || v48 == 101 )
           {
c04924       return 1;
           }
           else
           {
c04860       v50[0] = sub_1420E10A0(v48);
c04865       v60 = v5;
c04873       *(_QWORD *)&v59 = 0xB000000000000000uLL;
c0487c       v61 = v54;
c0488a       *((_QWORD *)&v59 + 1) = 0xB000000000000008uLL;
c04895       *(_QWORD *)&v56 = aFailedToDetach;
c0489a       *((_QWORD *)&v56 + 1) = 37;
c048a3       v51 = 2;
c048b0       v52 = (__int64)&v59;
c048ba       v55 = v56;
c048ce       sub_14057BE00(&v62, &v55, &v51);
c048db       *(_QWORD *)&v56 = asc_1429D9FA0;
c048e0       *((_QWORD *)&v56 + 1) = 6;
c048fb       v49 = sub_140696240(&v70, &v56, &v62, v50);
c04907       sub_141C05C30(a1, v49);
c04911       sub_14057FA60(&v70);
c0491b       sub_14057FA60(&v62);
c04920       return 0;
           }
         }
         else
         {
c04762     v50[0] = sub_1420E10A0(v46);
c04767     v60 = v5;
c04775     *(_QWORD *)&v59 = 0xB000000000000000uLL;
c0477e     v61 = v54;
c0478c     *((_QWORD *)&v59 + 1) = 0xB000000000000008uLL;
c04797     *(_QWORD *)&v56 = aFailedToExecut_0;
c0479c     *((_QWORD *)&v56 + 1) = 52;
c047a5     v51 = 2;
c047b2     v52 = (__int64)&v59;
c047bc     v55 = v56;
c047d0     sub_14057BE00(&v62, &v55, &v51);
c047dd     *(_QWORD *)&v56 = asc_1429D9FA0;
c047e2     *((_QWORD *)&v56 + 1) = 6;
c047fd     v47 = sub_140696240(&v70, &v56, &v62, v50);
c04809     sub_141C05C30(a1, v47);
c04813     sub_14057FA60(&v70);
c0481d     sub_14057FA60(&v62);
c04822     return 0;
         }
       }